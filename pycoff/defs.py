#!/usr/bin/python

import sys

from enum import Enum

class COFF_TYPE(Enum):
    ELF = 1
    MZ  = 2
    PE  = 3

class MAGIC:
    ELF = b'\x7fELF'
    MZ  = b'MZ'
    PE  = b'PE\0\0'

    
READ_BYTE = {
    'u': lambda f, x: int.from_bytes(f.read(x), byteorder=sys.byteorder),
    'i': lambda f, x: int.from_bytes(f.read(x), byteorder=sys.byteorder, signed=True),
    's': lambda f, x: bytes.decode(f.read(x).strip(b'\0'), errors="strict"),
}

