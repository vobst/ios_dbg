#!/usr/bin/env python3
#
# Cisco IOS GDB RSP Wrapper
# MIPS Version
#
# Authors:
#
#  Artem Kondratenko (@artkond) - Original version.
#  Valentin Obst - Python3 port and other goodies.

import capstone as cs
import logging
from typing import NoReturn

import ios_dbg.dbg_common as lib

lib.reg_map = {
    1: "at",
    2: "v0",
    3: "v1",
    4: "a0",
    5: "a1",
    6: "a2",
    7: "a3",
    8: "t0",
    9: "t1",
    10: "t2",
    11: "t3",
    12: "t4",
    13: "t5",
    14: "t6",
    15: "t7",
    16: "s0",
    17: "s1",
    18: "s2",
    19: "s3",
    20: "s4",
    21: "s5",
    22: "s6",
    23: "s7",
    24: "t8",
    25: "t9",
    26: "k0",
    27: "k1",
    28: "gp",
    29: "sp",
    30: "s8",
    31: "ra",
    37: "pc",
}

lib.num_regs = 39
lib.pc_reg = "pc"
lib.sp_reg = "sp"
lib.ra_reg = "ra"
lib.breakpoint_instruction = "0000000d"
lib.cs_arch = cs.CS_ARCH_MIPS
lib.cs_mode = cs.CS_MODE_MIPS32 | cs.CS_MODE_BIG_ENDIAN


def main() -> NoReturn:
    lib.main_loop(logging.INFO)


if __name__ == "__main__":
    main()
