#!/usr/bin/python

import sys

from enum import Enum

class COFF_TYPE(Enum):
    ELF = 1
    MZ  = 2
    PE  = 3
    AR  = 4

class MAGIC:
    ELF = b'\x7fELF'
    MZ  = b'MZ'
    PE  = b'PE\0\0'
    AR  = b'!<arch>\n'

