#!/usr/bin/python
from enum import Enum
import struct
import datetime

PE_MAGIC  = b'MZ'
ELF_MAGIC = b'\x7fELF'

def strcut_decode(obj, file, fmt, keys):
    byte = file.read(struct.calcsize(fmt))
    data = struct.unpack(fmt, byte)
    for i in range(len(keys)):
        setattr(obj, keys[i], data[i])

def strcut_encode(obj, fmt, keys):
    data = [getattr(obj, v) for v in keys]
    return struct.pack(fmt, *data)

def get_desc(key, desc_table):
    if type(desc_table) == dict:
        key = desc_table[key] if key in desc_table \
            else ' | '.join([desc_table[v] for v in desc_table.keys() if key & v])
    else:
        key = desc_table(key)
    return key

class Magic(Enum):
    PE  = 1
    ELF = 2

class CoffFileHeader:
    _FMT  = '=HHIIIHH'
    _KEYS = [
        'Machine', 'NumberOfSections', 'TimeDateStamp', 'PointerToSymbolTable', 'NumberOfSymbols', 'SizeOfOptionalHeader', 'Characteristics'
    ]
    _DESC = {
        'Machine': {
            0x14c: 'Intel 386',
            0x8664: 'x64',
        },
        'TimeDateStamp': lambda x: datetime.datetime.fromtimestamp(x),
        'Characteristics': {
            0x0002: 'IMAGE_FILE_EXECUTABLE_IMAGE',
            0x0020: 'IMAGE_FILE_LARGE_ADDRESS_AWARE',
            0x2000: 'IMAGE_FILE_DLL',
        },
    }

    def __init__(self, file):
        strcut_decode(self, file, CoffFileHeader._FMT, CoffFileHeader._KEYS)

    def __str__(self):
        res = {}
        for v in CoffFileHeader._KEYS:
            attr = getattr(self, v)
            if v in CoffFileHeader._DESC:
                attr = "{0:#x} ({1})".format(attr, get_desc(attr, CoffFileHeader._DESC[v]))
            res[v] = attr

        return str(res)

    def byte(self):
        return strcut_encode(self, CoffFileHeader._FMT, CoffFileHeader._KEYS)


class ELF:
    def __init__(self, file, path):
        self._file = file
        self._path = path

class PE:
    def __init__(self, file, path):
        self._file = file
        self._path = path

        self.__parser()

    def __def__(self):
        self._file.close()

    def __str__(self):
        return str(self.coff_file_header)

    def __check_signature(self):
        self._file.seek(0x3c)
        sign_offset = int.from_bytes(self._file.read(4), byteorder='little', signed=False)

        self._file.seek(sign_offset)
        sign = self._file.read(4)
        assert(sign == b'PE\0\0')

        self.coff_file_header_offset = self._file.tell()

    def __coff_file_header(self):
        self.coff_file_header = CoffFileHeader(self._file)

    def __option_header(self):
        # magic = self._file.read(2)
        magic = int.from_bytes(self._file.read(2), byteorder='little', signed=False)
        if magic == 0x10b:
            self._image_type = 'PE32'
        else:
            self._image_type = 'PE32+'

        print(self._image_type)

    def __parser(self):
        self.__check_signature()
        self.__coff_file_header()
        self.__option_header()

    def save(self):
        self._file.seek(self.coff_file_header_offset)
        byte = self.coff_file_header.byte()
        self._file.write(byte)


def check_magic(file):
    file.seek(0)
    magic = file.read(2)
    if magic == PE_MAGIC:
        return Magic.PE
    file.seek(0)
    magic = file.read(4)
    if magic == ELF_MAGIC:
        return Magic.ELF


def parser(file_path):
    file = open(file_path, 'rb+')
    magic = check_magic(file)

    if magic == Magic.PE:
        return PE(file, file_path)
    elif magic == Magic.ELF:
        return ELF(file, file_path)
