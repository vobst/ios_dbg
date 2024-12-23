# Authors:
#
#  Artem Kondratenko (@artkond) - Original MIPS version.
#  Nicholas Starke (@nstarke) - Original PowerPc version.
#  Valentin Obst - Python3 port and other goodies.
#
# Adapted from https://gist.github.com/nstarke/50a1519067f62c223e39a98ba32ed7d5

import serial
import time
from typing import NoReturn
import logging
from struct import pack, unpack
import sys
import capstone as cs
from termcolor import colored
import termios
import select
import tty

logging.basicConfig(level=logging.DEBUG)
logger: logging.Logger = logging.getLogger(__name__)

# reg number -> friendly name
reg_map: dict[int, str] = {}
reg_map_rev: dict[str, int] = {}

# heax_addr -> (bp_num, saved_insn)
breakpoints: dict[str, tuple[int, str]] = {}
breakpoints_count: int = 0

aslr_offset: int | None = None

isSerial: bool = True

num_regs: int = 0

pc_reg: str | None = None
sp_reg: str | None = None
ra_reg: str | None = None

breakpoint_instruction: str | None = ""

cs_arch: int | None = None
cs_mode: int | None = None


def print_help() -> None:
    print(
        """
Command reference:
exit                        - end debugging session
help                        - print this help
c                           - continue program execution
stepi                       - step into
nexti                       - step over
reg                         - print registers
setreg <reg_name> <value>   - set register value
break <addr> <aslr>         - set break point
del <break_num>             - delete breakpoint
info break                  - view breakpoints set
read <addr> <len>           - read memory
write <addr> <value         - write memory
search <addr> <pattern>     - search memory
gdb kernel                  - send "gdb kernel" command to IOS to launch GDB. Does not work on recent IOS versions.
dump <startaddr> <endaddr>  - dump memory within specified range
set_aslr_offset <offsetH>   - set aslr offset for code section
disas [<addr>] [aslr]       - disassemble at address. Optional "aslr" parameter to account for code randomization. Default is to disassemble at current PC.
interactive | int           - get a normal shell
stack [dwordsH]             - display the stack
debug <on|off|q>            - toogle debug output

You can also manually send any GDB RSP command.
    """
    )


if len(sys.argv) < 2:
    print_help()
    print("\n\nSpecify serial device as a parameter.")
    sys.exit(1)

ser: serial.Serial = serial.Serial(port=sys.argv[1], timeout=5)


def init_dbg(log_level) -> None:
    assert cs_mode is not None
    assert cs_arch is not None
    assert breakpoint_instruction is not None
    assert pc_reg is not None
    assert sp_reg is not None
    assert ra_reg is not None
    assert num_regs != 0
    assert len(reg_map) != 0

    logging.getLogger().setLevel(log_level)

    for k, v in reg_map.items():
        reg_map_rev[v] = k


# TODO: Copy-paste is weird with this solution.
def getch_non_blocking() -> str | None:
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)

    c: str | None = None
    try:
        tty.setraw(fd)
        if select.select([sys.stdin], [], [], 0)[0]:
            c = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return c


def OnInteractive() -> None:
    global ser

    recoding: bool = False
    rec_buf: bytearray = bytearray()

    saved_timeout: float | None = ser.timeout
    # make serial connection non-blocking
    ser.timeout = 0.0

    print(
        "\nInteractive mode. Escape sequence is ']]': ']]R' to toggle recoding, ']]B' for BREAK, ']]E' to exit."
    )

    saw_one_esc: bool = False
    in_esc: bool = False
    while True:
        # Check if there is input on the line.
        c: bytes = ser.read(1)
        if len(c) == 1:
            if recoding:
                rec_buf += c
            if c.isascii():
                c_str: str = c.decode("ASCII")
            else:
                c_str: str = "\\x%02x" % c[0]

            print(c_str, end="")
            sys.stdout.flush()

        # Check if there is user input.
        inp_buf: list[str] = []
        while True:
            ic: str | None = getch_non_blocking()
            if ic is not None:
                logging.debug(f"[OnInteractive] Got {ic}")
                inp_buf.append(ic)
            else:
                break
        inp: str = "".join(inp_buf)

        if inp == "]":
            if saw_one_esc:
                saw_one_esc = False
                in_esc = True
            elif in_esc:
                in_esc = False
                ser.write(inp.encode("ASCII"))
            else:
                saw_one_esc = True
        elif in_esc and inp != "":
            match inp:
                case "E":
                    break
                case "R":
                    if recoding:
                        logger.info(f"[OnInteractive] Recoding stopped.")
                        recoding = False
                    else:
                        logger.info(f"[OnInteractive] Recoding started.")
                        recoding = True
                case "B":
                    ser.send_break(duration=0.5)
                case _:
                    logger.error(
                        f"[OnInteractive] Unknown escape sequence: ]]{ic}"
                    )
            in_esc = False
        elif inp != "":
            ser.write(inp.encode("ASCII"))
        else:
            pass

    if len(rec_buf) > 0:
        with open("_rec.log", "wb") as f:
            logger.info(f"[OnInteractive] Saving recoding to: _rec.log.")
            f.write(rec_buf)

    ser.timeout = saved_timeout


def hexdump_gen(byte_string: bytes, _len=16, base_addr=0, n=0, sep="-"):
    FMT: str = "{}  {}  |{}|"
    not_shown: list[str] = ["  "]
    leader: int = (base_addr + n) % _len
    next_n: int = n + _len - leader
    while byte_string[n:]:
        col0: str = format(n + base_addr - leader, "08x")
        col1: list[str] = not_shown * leader
        col2: str = " " * leader
        leader: int = 0
        for i in bytearray(byte_string[n:next_n]):
            col1 += [format(i, "02x")]
            col2 += chr(i) if 31 < i < 127 else "."
        trailer: int = _len - len(col1)
        if trailer != 0:
            col1 += not_shown * trailer
            col2 += " " * trailer
        col1.insert(_len // 2, sep)
        yield FMT.format(col0, " ".join(col1), col2)
        n = next_n
        next_n += _len


def isValidDword(hexdword: str) -> bool:
    if len(hexdword) != 8:
        return False
    try:
        bytes.fromhex(hexdword)
    except TypeError:
        return False
    return True


def checksum(command: str) -> str:
    csum: int = 0
    reply: str = ""
    for c in command:
        csum: int = csum + ord(c)
    csum: int = csum % 256
    reply: str = "$" + command + "#%02x" % csum
    logger.debug(f"[checksum] <{command}> has checksum {hex(csum)}")
    return reply


def decodeRLE(data: bytes) -> bytes:
    i: int = 2
    int_mult: int = 0
    decoded_data: bytes = b""

    while i < len(data):
        # TODO: This might actually repeat the char once too often! (if the
        # encoding is somewhat sane ^^)
        if data[i : i + 1] == b"*":
            hex_mult: str = data[i + 1 : i + 3].decode("ASCII")
            int_mult: int = int(hex_mult, 16)
            logger.debug(f"[decodeRLE]: got multiplier, {hex_mult}, {int_mult}")
            for _ in range(0, int_mult):
                decoded_data: bytes = decoded_data + data[i - 1 : i]
            i: int = i + 3
        if data[i : i + 1] == b"#":
            break
        decoded_data: bytes = decoded_data + data[i : i + 1]
        i: int = i + 1
    return decoded_data


def CreateGetMemoryReq(address: str, length: str) -> str:
    cmd: str = "m" + address + "," + length
    formatted: str = checksum(cmd)
    formatted: str = formatted + "\n"
    return formatted


def DisplayRegisters(regbuffer: str) -> list[str]:
    regvals: list[str] = [""] * num_regs
    buf: str = regbuffer
    for k, dword in enumerate([buf[i : i + 8] for i in range(0, len(buf), 8)]):
        regvals[k] = dword
    return regvals


def GdbCommand(command: str) -> str:
    global isSerial
    logger.debug("[GdbCommand] sending: {}".format(checksum(command)))

    ser.write("{}".format(checksum(command)).encode("ASCII"))

    if command == "c":
        OnInteractive()
        return ""

    out: bytes = b""
    char: bytes = b""
    while char != b"#":
        char: bytes = ser.read(1)
        out: bytes = out + char
    # skip checksum
    ser.read(2)
    logger.debug("[GdbCommand] Raw output from cisco: {}".format(out))

    newrle: bytes = decodeRLE(out)
    logger.debug("[GdbCommand] Decode RLE: {}".format(newrle))

    decoded: str = newrle.decode("ASCII")
    logger.debug("[GdbCommand] decoded: {}".format(decoded))

    lex: list[str] = decoded.split("||||")
    if len(lex) > 1:
        logger.info(f"[GdbCommand] Remote sent prefix: {lex[:-1]}")

    decoded: str = lex[-1]

    while decoded[0] == "|" or decoded[0] == "+" or decoded[0] == "$":
        decoded: str = decoded[1:]

    return decoded


def OnReadReg() -> list[str]:
    raw_registers: str = GdbCommand("g")
    regs: list[str] = DisplayRegisters(raw_registers)
    print("All registers:", end="")
    counter: int = 0
    for _, reg_name in reg_map.items():
        if regs[reg_map_rev[reg_name]]:
            if counter % 4 == 0:
                print("")
            counter += 1
            print(
                "{}: {}\t".format(reg_name, regs[reg_map_rev[reg_name]]), end=""
            )
    print("")
    print("Control registers:")
    print(
        (
            "PC: {} SP: {} RA: {}".format(
                colored(
                    regs[reg_map_rev[pc_reg]] if pc_reg is not None else "n.a.",
                    "red",
                ),
                colored(
                    regs[reg_map_rev[sp_reg]] if sp_reg is not None else "n.a.",
                    "yellow",
                ),
                colored(
                    regs[reg_map_rev[ra_reg]] if ra_reg is not None else "n.a.",
                    "red",
                ),
            )
        ),
    )
    return regs


def OnWriteReg(command: str) -> bool | None:
    lex: list[str] = command.split(" ")
    (_, reg_name, reg_val) = lex[0:3]

    if reg_name not in reg_map_rev:
        logger.error(f"[OnWriteReg] Unknown register specified: {reg_name}")
        return
    if not isValidDword(reg_val):
        logger.error(f"[OnWriteReg] Invalid register value supplied: {reg_val}")
        return

    logger.debug(
        "[OnWriteReg] Setting register {} with value {}".format(
            reg_name, reg_val
        )
    )
    regs: list[str] = DisplayRegisters(GdbCommand("g"))
    regs[reg_map_rev[reg_name]] = reg_val.lower()
    buf: str = "".join(regs)
    logger.debug("[OnWriteReg] Writing register buffer: {}".format(buf))
    res: str = GdbCommand("G{}".format(buf))

    if "OK" in res:
        logger.debug(f"[OnWriteReg] OK: {res}")
        return True
    else:
        logger.error(f"[OnWriteReg] ERR: {res}")
        return None


def OnReadMem(addr: str, length: int) -> str | None:
    if not isValidDword(addr):
        logger.error("[OnReadMem] Invalid address supplied")
        return None
    if length > 199:
        logger.error("[OnReadMem] Maximum length of 199 exceeded")
        return None
    res: str = GdbCommand("m{},{}".format(addr.lower(), hex(length)[2:]))
    if res.startswith("E0"):
        return None
    else:
        return res


def OnWriteMem(addr: str, data: str) -> bool | None:
    res: str = GdbCommand("M{},{}:{}".format(addr.lower(), len(data) / 2, data))
    if "OK" in res:
        logger.debug(f"[OnWriteMem] OK: {res}")
        return True
    else:
        logger.error(f"[OnWriteMem] ERR: {res}")
        return None


def hex2int(s) -> int:
    return unpack(">I", bytes.fromhex(s))[0]


def int2hex(num: int) -> str:
    return pack(">I", num & 0xFFFFFFFF).hex()


# TODO: Does not work on PPC.
def OnBreak(command: str):
    global breakpoints
    global breakpoints_count
    lex: list[str] = command.split(" ")

    (_, addr) = lex[0:2]
    if not isValidDword(addr):
        logger.error(f"[OnBreak] Invalid address supplied: {addr}")
        return
    if len(lex) == 3:
        if lex[2] == "aslr" and aslr_offset != None:
            logger.info(
                f"[OnBreak] Adding ASLR offset to breakpoint address: {aslr_offset}"
            )
            addr: str = int2hex(hex2int(addr) + aslr_offset)
    addr: str = addr.lower().rstrip()
    if addr in breakpoints:
        logger.info(f"[OnBreak] Breakpoint already set at {addr}")
        return
    opcode_to_save: str | None = OnReadMem(addr, 4)
    if opcode_to_save is None:
        logger.error(
            "[OnBreak] Can't set breakpoint at {}. Read error".format(addr)
        )
        return
    assert breakpoint_instruction is not None
    res: bool | None = OnWriteMem(addr, breakpoint_instruction)
    if res is not None:
        breakpoints_count += 1
        breakpoints[addr] = (breakpoints_count, opcode_to_save)
        logger.info("[OnBreak] Breakpoint set at {}".format(addr))
    else:
        logger.error(
            "[OnBreak] Can't set breakpoint at {}. Error writing".format(addr)
        )


def OnDelBreak(command: str) -> None:
    global breakpoints
    global breakpoints_count

    bp_found = False
    (_, bp_num) = command.rstrip().split(" ")

    logger.debug(f"[OnDelBreak] deleting BP no. {bp_num}")

    for bp_addr, bp_num__insn in breakpoints.items():
        try:
            if bp_num__insn[0] == int(bp_num):
                bp_found = True
                res: bool | None = OnWriteMem(bp_addr, bp_num__insn[1])
                if res is not None:
                    del breakpoints[bp_addr]
                    logger.info(
                        "[OnDelBreak] Deleted breakpoint {}".format(bp_num)
                    )
                    break
                else:
                    logger.error(
                        "[OnDelBreak] Error deleting breakpoint {} at {}".format(
                            bp_num, bp_addr
                        )
                    )
                    return
        except ValueError:
            logger.error("[OnDelBreak] Invalid breakpoint num supplied")
            return

    if bp_found is False:
        logger.error(f"[OnDelBreak] Breakpoint not found: {bp_num}")


def OnSearchMem(addr: str, pattern: str) -> None:
    cur_addr: str = addr.lower()
    buf: str = ""
    i: int = 0

    if pattern % 2 != 0:
        logger.error(f"[OnSearchMem] Invalid pattern.")
        return
    if len(pattern) // 2 > 0xC7:
        logger.error(f"[OnSearchMem] Pattern too long.")
        return
    try:
        bytes.fromhex(pattern)
    except ValueError:
        logger.error(f"[OnSearchMem] Invalid pattern.")
        return

    while True:
        i += 1
        mem: str = GdbCommand("m{},00c7".format(cur_addr))
        buf += mem
        if i % 1000 == 0:
            print(cur_addr)
            print(hexdump_gen(bytes.fromhex(mem)))
        if pattern in buf[-min(2 * len(mem), len(buf)) :]:
            print("FOUND at {}".format(cur_addr))
            return
        cur_addr = pack(
            ">I", unpack(">I", bytes.fromhex(cur_addr))[0] + 0xC7
        ).hex()


def OnListBreak() -> None:
    global breakpoints
    global breakpoints_count

    for k, v in breakpoints.items():
        print("{}: {}".format(v[0], k))


def OnStepInto() -> None:
    ser.write("$s#73\r\n".encode("ASCII"))
    ser.read(5)
    OnReadReg()
    OnDisas("disas")


def OnNext() -> None:
    regs: list[str] = OnReadReg()
    assert pc_reg is not None
    pc: int = unpack(">I", bytes.fromhex(regs[reg_map_rev[pc_reg]]))[0]
    pc_after_branch: int = pc + 8
    pc_after_branch_in_hex: str = pack(">I", pc_after_branch).hex()
    logger.debug(f"[OnNext] PC {hex(pc)}, next PC {pc_after_branch_in_hex}")

    OnBreak("break {}".format(pc_after_branch_in_hex))
    GdbCommand("c")
    OnReadReg()
    OnDelBreak("del {}".format(breakpoints[pc_after_branch_in_hex][0]))


def OnDumpMemory(start: str, stop: str) -> str | None:
    buf: str = ""

    logger.info(f"[OnDumpMemory] Dumping memory from {start} to {stop}")

    if not isValidDword(start) or not isValidDword(stop):
        logger.error("[OnDumpMemory] Invalid memory range specified")
        return

    cur_addr: str = start

    counter: int = 0
    last_time: float = time.time()
    progress_step = 10

    # The maximum number of bytes that can be read at once.
    MAX_READ = 0xC7
    while hex2int(cur_addr) < hex2int(stop):
        bytes_left: int = hex2int(stop) - hex2int(cur_addr)
        num_to_read = min(bytes_left, MAX_READ)

        res: str = GdbCommand("m{},00{:x}".format(cur_addr, num_to_read))

        if counter % progress_step == 0:
            # every 1.94KiB
            cur_time: float = time.time()
            time_per_iter: float = (cur_time - last_time) / progress_step
            bytes_left: int = hex2int(stop) - hex2int(cur_addr)
            bitrate: float = (MAX_READ / time_per_iter) * 8
            iter_left: float = bytes_left / MAX_READ
            time_left: float = iter_left * time_per_iter

            logger.info(
                f"[OnDumpMemory] Progress: current address {cur_addr} ({hex(bytes_left)} bytes left, ~{time_left}s left, speed {bitrate}b/s)"
            )

            last_time: float = cur_time
        counter += 1

        logger.debug(
            "[OnDumpMemory] Dumping at {} len {}".format(cur_addr, len(res))
        )

        cur_addr: str = int2hex(hex2int(cur_addr) + num_to_read)
        buf += res

    return buf


def OnSetAslrOffset(command: str) -> None:
    global aslr_offset

    (_, offset) = command.rstrip().split(" ")
    aslr_offset = hex2int(offset)
    logger.info("[OnSetAslrOffset] ASLR offset set to: 0x{}".format(offset))


def OnShowStack(dwords: str | None):
    global sp_reg
    global reg_map_rev
    assert sp_reg is not None

    if dwords is not None:
        dwords_int: int = int(dwords, 16)
    else:
        dwords_int: int = 10

    # read current SP
    regs: list[str] = DisplayRegisters(GdbCommand("g"))
    sp: int = hex2int(regs[reg_map_rev[sp_reg]])

    buf: str | None = OnReadMem(int2hex(sp), dwords_int * 4)
    if buf is None:
        logger.error("[OnShowStack] Failed to read stack memory.")
        return
    for n, dword in enumerate([buf[i : i + 8] for i in range(0, len(buf), 8)]):
        print(colored("0x%08x" % (sp + n * 4), "yellow") + "\t" + "%s" % dword)


def OnDisas(command: str) -> None:
    global cs_arch
    global cs_mode
    global pc_reg
    assert cs_mode is not None
    assert pc_reg is not None
    assert cs_arch is not None

    lex: list[str] = command.rstrip().split(" ")

    # read current PC
    regs: list[str] = DisplayRegisters(GdbCommand("g"))
    pc: int = hex2int(regs[reg_map_rev[pc_reg]])

    # overwrite with optional absolute PC
    for lexem in lex[1:]:
        if lexem != "aslr":
            if not isValidDword(lexem):
                logger.error(f"[OnDisas] Invalid address supplied: {lexem}")
                return
            pc: int = hex2int(lexem)

    if pc % 4 != 0:
        logger.error("[OnDisas] Unaligned PC value")
        return

    logger.debug(f"[OnDisas] PC = {hex(pc)}")

    buf: str | None = OnReadMem(int2hex(pc - 20 * 4), 40 * 4)
    if buf is None:
        logger.error("[OnDisas] Failed to read code")
        return

    md: cs.Cs = cs.Cs(cs_arch, cs_mode)

    if len(lex) > 1:
        if lex[1] == "aslr" and aslr_offset != None:
            pc -= aslr_offset

    if len(buf) % 8 != 0:
        logger.error(f"[OnDisas] Read incomplete instruction.")
        return

    for insn_idx in range(0, len(buf) // 8):
        insn_addr: int = pc - 20 * 4 + insn_idx * 4
        insn_hex: str = buf[8 * insn_idx : 8 * insn_idx + 8]
        disasm: list[cs.CsInsn] = list(
            md.disasm(bytes.fromhex(insn_hex), insn_addr)
        )
        if len(disasm) == 0:
            logger.error(
                f"[OnDisas] Can not disassemble instruction {insn_hex} at {hex(insn_addr)}"
            )
            continue

        for i in disasm:
            color = "green" if i.address == pc else "blue"
            print(
                "%s\t%s\t%s\t%s"
                % (
                    colored("0x%x" % i.address, "red"),
                    insn_hex,
                    colored(i.mnemonic, color),
                    colored(i.op_str, color),
                )
            )


def main_loop(log_level) -> NoReturn:
    init_dbg(log_level)

    while True:
        try:
            command: str = input(colored("> command: ", "green")).rstrip()
            if command == "exit":
                sys.exit(0)
            elif command == "help":
                print_help()
            elif command == "c":
                GdbCommand("c")
            elif command == "stepi":
                OnStepInto()
            elif command == "nexti":
                OnNext()
            elif command == "reg":
                OnReadReg()
            elif command.startswith("setreg"):
                OnWriteReg(command)
            elif command.startswith("break"):
                OnBreak(command)
            elif command.startswith("del"):
                OnDelBreak(command)
            elif command.startswith("info b"):
                OnListBreak()
            elif command.startswith("read"):
                _, start, length = command.split(" ")
                buf: str | None = OnReadMem(start, int(length))
                if buf is None:
                    print(f"Memory read failed: {start}, {length}")
                else:
                    for line in hexdump_gen(
                        bytes.fromhex(buf), base_addr=hex2int(start), sep=" "
                    ):
                        print(line)
            elif command.startswith("write"):
                _, dest, value = command.split(" ")
                try:
                    bytes.fromhex(value)
                    OnWriteMem(dest, value)
                except ValueError as V:
                    print(V)
                    print(f"Invalid hex value: {value}")
            elif command.startswith("search"):
                _, addr, pattern = command.split(" ")
                OnSearchMem(addr, pattern)
            elif command.startswith("gdb kernel"):
                ser.write("{}\n".format("gdb kernel").encode("ASCII"))
            elif command.startswith("dump"):
                _, start, stop = command.split(" ")
                start: str = start.lower()
                stop: str = stop.lower()
                buf: str | None = OnDumpMemory(start, stop)
                if buf is None:
                    logger.error("[MAIN] Failed to dump memory.")
                    continue
                else:
                    fname = f"{start}_{stop}.dump"
                    with open(fname, "wb") as f:
                        f.write(bytes.fromhex(buf))
                    logger.info(f'[MAIN] Wrote memory dump to "{fname}"')
            elif command.startswith("set_aslr_offset"):
                OnSetAslrOffset(command)
            elif command.startswith("disas"):
                OnDisas(command)
            elif command.startswith("int"):
                OnInteractive()
            elif command.startswith("stack"):
                lex: list[str] = command.split(" ")
                OnShowStack(lex[1] if len(lex) > 1 else None)
            elif command.startswith("debug"):
                _, switch = command.split(" ")
                match switch:
                    case "on":
                        logging.getLogger().setLevel(logging.DEBUG)
                    case "off":
                        logging.getLogger().setLevel(logging.INFO)
                    case "q":
                        logging.getLogger().setLevel(logging.ERROR)
                    case _:
                        logger.error(f"Bad debug switch: {switch}")
            else:

                ans: str = input(
                    "Command not recognized.\nDo you want to send raw command: {} ? [yes]".format(
                        checksum(command.rstrip())
                    )
                )
                if ans == "" or ans == "yes":
                    reply: str = GdbCommand(command.rstrip())
                    print("Cisco response:", reply.rstrip())
        except (
            KeyboardInterrupt,
            serial.SerialException,
            ValueError,
            TypeError,
        ) as e:
            print("\n{}".format(e))
            print('Type "exit" to end debugging session')
