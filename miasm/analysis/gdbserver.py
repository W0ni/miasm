#-*- coding:utf-8 -*-

from __future__ import print_function
from future.builtins import map, range

from miasm.core.utils import decode_hex, encode_hex, int_to_byte
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
import socket
import struct
import time
import logging
from io import BytesIO
import miasm.analysis.debugging as debugging
from miasm.jitter.jitload import ExceptionHandle

class GdbServer(object):

    "Debugguer binding for GDBServer protocol"

    general_registers_order = []
    general_registers_size = {}  # RegName : Size in octet
    status = b"S05"

    def __init__(self, dbg, port=4455):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('localhost', port))
        server.listen(1)
        self.server = server
        self.dbg = dbg

    # Communication methods

    def compute_checksum(self, data):
        return encode_hex(bytes([sum(bytes(data)) & 0xff]))

    def get_messages(self):
        all_data = b""
        while True:
            data = self.sock.recv(4096)
            all_data += data
            if (len(data) > 3) and data[-3] == b'#'[0]:
                break

        logging.debug("<- %r", all_data)
        self.recv_queue += self.parse_messages(all_data)

    def parse_messages(self, data):
        buf = BytesIO(data)
        msgs = []

        while (buf.tell() < len(data)):
            token = buf.read(1)
            if token == b"+":
                continue
            if token == b"-":
                raise NotImplementedError("Resend packet")
            if token == b"$":
                packet_data = b""
                c = buf.read(1)
                while c != b"#":
                    packet_data += c
                    c = buf.read(1)
                checksum = buf.read(2)
                if checksum != self.compute_checksum(packet_data):
                    raise ValueError("Incorrect checksum")
                msgs.append(packet_data)

        return msgs

    def send_string(self, s):
        self.send_queue.append(b"O" + encode_hex(s))

    def process_messages(self):
        while self.recv_queue:
            msg = self.recv_queue.pop(0)
            logging.debug(msg)
            print(msg)
            buf = BytesIO(msg)
            msg_type = buf.read(1)

            self.send_queue.append(b"+")

            if msg_type == b"q":
                if msg.startswith(b"qSupported"):
                    self.send_queue.append(b"PacketSize=3fff")
                elif msg.startswith(b"qC"):
                    # Current thread
                    self.send_queue.append(b"")
                elif msg.startswith(b"qAttached"):
                    # Not supported
                    self.send_queue.append(b"")
                elif msg.startswith(b"qTStatus"):
                    # Not supported
                    self.send_queue.append(b"")
                elif msg.startswith(b"qfThreadInfo"):
                    # Not supported
                    self.send_queue.append(b"")
                elif msg.startswith(b"qL"):
                    # Not supported
                    self.send_queue.append(b"")
                elif msg.startswith(b"qSymbol::"):
                    # Not supported
                    self.send_queue.append(b"OK")

                elif msg.startswith(b"qOffsets"):
                    # Not supported
                    self.send_queue.append(b"")
                elif msg.startswith(b"qRcmd"):
                    cmd = decode_hex(msg.split(b'qRcmd,', 1)[1].split(b'#', 1)[0])
                    if cmd == b"info mem":
                        all_memory = self.dbg.myjit.vm.get_all_memory()
                        sections = list(all_memory)
                        result_mappings = b""
                        for i in range(len(sections)):
                            addr = sections[i]
                            access = all_memory[addr]['access']
                            perms = b""
                            perms += b"r" if access & PAGE_READ else b"-"
                            perms += b"w" if access & PAGE_WRITE else b"-"
                            result_mappings += b"0x%x-0x%x 0x%x -%s\n" % (addr, all_memory[addr]['size'] + addr, addr - sections[0], perms)
                        print(result_mappings)
                        self.send_queue.append(encode_hex(result_mappings))
                    else:
                        raise NotImplementedError(cmd)

                else:
                    self.send_queue.append(b"")
                    logging.error("unknown q packet") 
            elif msg_type == b'Q':
                # Not supported
                self.send_queue.append(b"")
                logging.error("unknown Q packet")
            elif msg_type == b"H":
                # Set current thread
                self.send_queue.append(b"OK")

            elif msg_type == b"?":
                # Report why the target halted
                self.send_queue.append(self.status)  # TRAP signal

            elif msg_type == b"g":
                # Report all general register values
                self.send_queue.append(self.report_general_register_values())

            elif msg_type == b"p":
                # Read a specific register
                reg_num = int(buf.read(), 16)
                self.send_queue.append(self.read_register(reg_num))

            elif msg_type == b"P":
                # Set a specific register
                reg_num, value = buf.read().split(b"=")
                reg_num = int(reg_num, 16)
                value = int(encode_hex(decode_hex(value)[::-1]), 16)
                self.set_register(reg_num, value)
                self.send_queue.append(b"OK")

            elif msg_type == b"m":
                # Read memory
                addr, size = (int(x, 16) for x in buf.read().split(b",", 1))
                self.send_queue.append(self.read_memory(addr, size))

            elif msg_type == b"k":
                # Kill
                self.sock.close()
                self.send_queue = []
                self.sock = None

            elif msg_type == b"!":
                # Extending debugging will be used
                self.send_queue.append(b"OK")

            elif msg_type == b"v":
                if msg == b"vCont?":
                    # Is vCont supported ?
                    self.send_queue.append(b"")
                else:
                    print("unkown v packet")
                    self.send_queue.append(b"")

            elif msg_type == b"s":
                # Step
                self.dbg.step()
                self.send_queue.append(b"S05")  # TRAP signal

            elif msg_type == b"Z":
                # Add breakpoint or watchpoint
                bp_type = buf.read(1)
                if bp_type == b"0":
                    # Exec breakpoint
                    assert(buf.read(1) == b",")
                    addr, size = (int(x, 16) for x in buf.read().split(b",", 1))

                    if size != 1:
                        logging.error("Bigger size")
                    self.dbg.add_breakpoint(addr)
                    self.send_queue.append(b"OK")

                elif bp_type == b"1":
                    # Hardware BP
                    assert(buf.read(1) == b",")
                    addr, size = (int(x, 16) for x in buf.read().split(b",", 1))

                    self.dbg.add_memory_breakpoint(
                        addr,
                        size,
                        read=True,
                        write=True
                    )
                    self.send_queue.append(b"OK")

                elif bp_type in [b"2", b"3", b"4"]:
                    # Memory breakpoint
                    assert(buf.read(1) == b",")
                    read = bp_type in [b"3", b"4"]
                    write = bp_type in [b"2", b"4"]
                    addr, size = (int(x, 16) for x in buf.read().split(b",", 1))

                    self.dbg.add_memory_breakpoint(
                        addr,
                        size,
                        read=read,
                        write=write
                    )
                    self.send_queue.append(b"OK")

                else:
                    raise ValueError("Impossible value")

            elif msg_type == b"z":
                # Remove breakpoint or watchpoint
                bp_type = buf.read(1)
                if bp_type == b"0":
                    # Exec breakpoint
                    assert(buf.read(1) == b",")
                    addr, size = (int(x, 16) for x in buf.read().split(b",", 1))

                    if size != 1:
                        logging.error("Bigger size")
                    dbgsoft = self.dbg.get_breakpoint_by_addr(addr)
                    assert(len(dbgsoft) == 1)
                    self.dbg.remove_breakpoint(dbgsoft[0])
                    self.send_queue.append(b"OK")

                elif bp_type == b"1":
                    # Hardware BP
                    assert(buf.read(1) == b",")
                    addr, size = (int(x, 16) for x in buf.read().split(b",", 1))
                    self.dbg.remove_memory_breakpoint_by_addr_access(
                        addr,
                        read=True,
                        write=True
                    )
                    self.send_queue.append(b"OK")

                elif bp_type in [b"2", b"3", b"4"]:
                    # Memory breakpoint
                    assert(buf.read(1) == b",")
                    read = bp_type in [b"3", b"4"]
                    write = bp_type in [b"2", b"4"]
                    addr, size = (int(x, 16) for x in buf.read().split(b",", 1))

                    self.dbg.remove_memory_breakpoint_by_addr_access(
                        addr,
                        read=read,
                        write=write
                    )
                    self.send_queue.append(b"OK")

                else:
                    raise ValueError("Impossible value")

            elif msg_type == b"c":
                # Continue
                self.status = b""
                self.send_messages()
                ret = self.dbg.run()
                if isinstance(ret, debugging.DebugBreakpointSoft):
                    self.status = b"S05"
                    self.send_queue.append(b"S05")  # TRAP signal
                elif isinstance(ret, ExceptionHandle):
                    if ret == ExceptionHandle.memoryBreakpoint():
                        self.status = b"S05"
                        self.send_queue.append(b"S05")
                    else:
                        raise NotImplementedError("Unknown Except")
                elif isinstance(ret, debugging.DebugBreakpointTerminate):
                    # Connection should close, but keep it running as a TRAP
                    # The connection will be close on instance destruction
                    print(ret)
                    self.status = b"S05"
                    self.send_queue.append(b"S05")
                else:
                    raise NotImplementedError()
            elif msg_type == b'C':
                signal = buf.read(2)
                self.send_queue.append(b"X" + signal)
            else:
                raise NotImplementedError(
                    "Not implemented: message type %r" % msg_type
                )

    def send_messages(self):
        for msg in self.send_queue:
            if msg == b"+":
                data = b"+"
            else:
                data = b"$%s#%s" % (msg, self.compute_checksum(msg))
            logging.debug("-> %r", data)
            self.sock.send(data)
        self.send_queue = []

    def main_loop(self):
        self.recv_queue = []
        self.send_queue = []

        self.send_string(b"Test\n")

        while (self.sock):
            self.get_messages()
            self.process_messages()
            self.send_messages()

    def run(self):
        self.sock, self.address = self.server.accept()
        self.main_loop()

    # Debugguer processing methods
    def report_general_register_values(self):
        s = b""
        for i in range(len(self.general_registers_order)):
            s += self.read_register(i)
        return s

    def read_register(self, reg_num):
        if reg_num > len(self.general_registers_order):
            return b''
        reg_name = self.general_registers_order[reg_num]
        reg_value = self.read_register_by_name(reg_name)
        size = self.general_registers_size[reg_name]

        pack_token = ""
        if size == 1:
            pack_token = "<B"
        elif size == 2:
            pack_token = "<H"
        elif size == 4:
            pack_token = "<I"
        elif size == 8:
            pack_token = "<Q"
        else:
            raise NotImplementedError("Unknown size")

        return encode_hex(struct.pack(pack_token, reg_value))

    def set_register(self, reg_num, value):
        reg_name = self.general_registers_order[reg_num]
        self.dbg.set_reg_value(reg_name, value)

    def read_register_by_name(self, reg_name):
        return self.dbg.get_reg_value(reg_name)

    def read_memory(self, addr, size):
        except_flag_vm = self.dbg.myjit.vm.get_exception()
        try:
            return encode_hex(self.dbg.get_mem_raw(addr, size))
        except RuntimeError:
            self.dbg.myjit.vm.set_exception(except_flag_vm)
            return b"00" * size


class GdbServer_x86_32(GdbServer):

    "Extend GdbServer for x86 32bits purposes"

    general_registers_order = [
        "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI",
        "EDI", "EIP", "EFLAGS", "CS", "SS", "DS", "ES",
        "FS", "GS"
    ]

    general_registers_size = {
        "EAX": 4,
        "ECX": 4,
        "EDX": 4,
        "EBX": 4,
        "ESP": 4,
        "EBP": 4,
        "ESI": 4,
        "EDI": 4,
        "EIP": 4,
        "EFLAGS": 2,
        "CS": 2,
        "SS": 2,
        "DS": 2,
        "ES": 2,
        "FS": 2,
        "GS": 2
    }

    register_ignore = [
        "tf", "i_f", "nt", "rf", "vm", "ac", "vif", "vip", "i_d"
    ]

    def read_register_by_name(self, reg_name):
        sup_func = super(GdbServer_x86_32, self).read_register_by_name

        # Assert EIP on pc jitter
        if reg_name == "EIP":
            return self.dbg.myjit.pc

        # EFLAGS case
        if reg_name == "EFLAGS":
            val = 0
            eflags_args = [
                "cf", 1, "pf", 0, "af", 0, "zf", "nf", "tf", "i_f", "df", "of"
            ]
            eflags_args += ["nt", 0, "rf", "vm", "ac", "vif", "vip", "i_d"]
            eflags_args += [0] * 10

            for i, arg in enumerate(eflags_args):
                if isinstance(arg, str):
                    if arg not in self.register_ignore:
                        to_add = sup_func(arg)
                    else:
                        to_add = 0
                else:
                    to_add = arg

                val |= (to_add << i)
            return val
        else:
            return sup_func(reg_name)

class GdbServer_x86_64(GdbServer):

    "Extend GdbServer for x86 64bits purposes"

    general_registers_order = [
        "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP",
        "RSP", "R8", "R9", "R10", "R11", "R12", "R13", "R14",
        "R15", "RIP", "EFLAGS", "CS", "SS", "DS", "ES",
        "FS", "GS"
    ]

    general_registers_size = {
        "RAX": 8,
        "RCX": 8,
        "RDX": 8,
        "RBX": 8,
        "RSP": 8,
        "RBP": 8,
        "RSI": 8,
        "RDI": 8,
        "RIP": 8,
        "R8" : 8,
        "R9" : 8,
        "R10" : 8,
        "R11": 8,
        "R12" : 8,
        "R13" : 8,
        "R14" : 8,
        "R15" : 8,
        "EFLAGS": 4,
        "CS": 4,
        "SS": 4,
        "DS": 4,
        "ES": 4,
        "FS": 4,
        "GS": 4
    }

    register_ignore = [
        "tf", "i_f", "nt", "rf", "vm", "ac", "vif", "vip", "i_d"
    ]

    def read_register_by_name(self, reg_name):
        sup_func = super(GdbServer_x86_64, self).read_register_by_name

        # Assert EIP on pc jitter
        if reg_name == "RIP":
            return self.dbg.myjit.pc

        # EFLAGS case
        if reg_name == "EFLAGS":
            val = 0
            eflags_args = [
                "cf", 1, "pf", 0, "af", 0, "zf", "nf", "tf", "i_f", "df", "of"
            ]
            eflags_args += ["nt", 0, "rf", "vm", "ac", "vif", "vip", "i_d"]
            eflags_args += [0] * 10

            for i, arg in enumerate(eflags_args):
                if isinstance(arg, str):
                    if arg not in self.register_ignore:
                        to_add = sup_func(arg)
                    else:
                        to_add = 0
                else:
                    to_add = arg

                val |= (to_add << i)
            return val
        else:
            return sup_func(reg_name)



class GdbServer_msp430(GdbServer):

    "Extend GdbServer for msp430 purposes"

    general_registers_order = [
        "PC", "SP", "SR", "R3", "R4", "R5", "R6", "R7",
        "R8", "R9", "R10", "R11", "R12", "R13", "R14",
        "R15"
    ]

    general_registers_size = {
        "PC": 2,
        "SP": 2,
        "SR": 2,
        "R3": 2,
        "R4": 2,
        "R5": 2,
        "R6": 2,
        "R7": 2,
        "R8": 2,
        "R9": 2,
        "R10": 2,
        "R11": 2,
        "R12": 2,
        "R13": 2,
        "R14": 2,
        "R15": 2
    }

    def read_register_by_name(self, reg_name):
        sup_func = super(GdbServer_msp430, self).read_register_by_name
        if reg_name == "SR":
            o = sup_func('res')
            o <<= 1
            o |= sup_func('of')
            o <<= 1
            o |= sup_func('scg1')
            o <<= 1
            o |= sup_func('scg0')
            o <<= 1
            o |= sup_func('osc')
            o <<= 1
            o |= sup_func('cpuoff')
            o <<= 1
            o |= sup_func('gie')
            o <<= 1
            o |= sup_func('nf')
            o <<= 1
            o |= sup_func('zf')
            o <<= 1
            o |= sup_func('cf')

            return o
        else:
            return sup_func(reg_name)


class GdbServer_arm(GdbServer):

    "Extend GdbServer for arm purposes"

    general_registers_order = [
        *["R%d" %i for i in range(13)], "SP", "LR", "PC", "CPSR", *["XXX" for _ in range(41-16)],
    ]

    general_registers_size = {
        "PC": 4,
        "SP": 4,
        "CPSR": 4,
        "LR": 4,
        "R0": 4,
        "R1": 4,
        "R2": 4,
        "R3": 4,
        "R4": 4,
        "R5": 4,
        "R6": 4,
        "R7": 4,
        "R8": 4,
        "R9": 4,
        "R10":4,
        "R11": 4,
        "R12": 4,
        "XXX": 4
    }

    def read_register_by_name(self, reg_name):
        sup_func = super(GdbServer_arm, self).read_register_by_name
        if reg_name == "CPSR":
            cpsr = sup_func('nf') << 32
            cpsr |= sup_func('zf') << 31
            cpsr |= sup_func('cf') << 30
            cpsr |= sup_func('of') << 29

            cpsr |= sup_func('ge3') << 19
            cpsr |= sup_func('ge2') << 18
            cpsr |= sup_func('ge1') << 17
            cpsr |= sup_func('ge0') << 16
            return cpsr
        elif reg_name == 'XXX':
            return 0
        else:
            return sup_func(reg_name)
