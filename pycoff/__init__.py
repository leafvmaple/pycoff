#!/usr/bin/python

from .defs import COFF_TYPE
from .pe import PE
from .elf import ELF
from .utility import check_magic

def parser(file_path):
    file = open(file_path, 'rb+')
    coff_type = check_magic(file)

    if coff_type == COFF_TYPE.PE:
        return PE(file, file_path)
    elif coff_type == COFF_TYPE.ELF:
        return ELF(file, file_path)
