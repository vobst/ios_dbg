#!/usr/bin/env python3
#
# Cisco IOS GDB RSP Wrapper
# PowerPC Version
#
# Authors:
#
#  Artem Kondratenko (@artkond) - Original MIPS version.
#  Nicholas Starke (@nstarke) - Original PowerPc version.
#  Valentin Obst - Python3 port and other goodies.
#
# Adapted from https://gist.github.com/nstarke/50a1519067f62c223e39a98ba32ed7d5
#
# This does not take into account floating point registers.
#

import capstone as cs
import logging
from typing import NoReturn

import ios_dbg.dbg_common as lib

lib.reg_map = {
    1: "cr",
    2: "lr",
    3: "ctr",
    4: "gpr0",
    5: "gpr1",
    6: "gpr2",
    7: "gpr3",
    8: "gpr4",
    9: "gpr5",
    10: "gpr6",
    11: "gpr7",
    12: "gpr8",
    13: "gpr9",
    14: "gpr10",
    15: "gpr11",
    16: "gpr12",
    17: "gpr13",
    18: "gpr14",
    19: "gpr15",
    20: "gpr16",
    21: "gpr17",
    22: "gpr19",
    23: "gpr19",
    24: "gpr20",
    25: "gpr21",
    26: "gpr22",
    27: "gpr23",
    28: "gpr24",
    29: "gpr25",
    30: "gpr26",
    31: "gpr27",
    32: "gpr28",
    33: "gpr29",
    34: "gpr30",
    35: "gpr31",
    36: "pc",
    37: "sp",
}

lib.num_regs = 90
lib.pc_reg = "pc"
lib.sp_reg = "sp"
lib.ra_reg = "lr"
lib.breakpoint_instruction = "7fe00008"
lib.cs_arch = cs.CS_ARCH_PPC
lib.cs_mode = cs.CS_MODE_BIG_ENDIAN


def main() -> NoReturn:
    lib.main_loop(logging.DEBUG)


if __name__ == "__main__":
    main()
