#!/usr/bin/python
from enum import Enum
import sys
import struct
import datetime
import json

PE_MAGIC  = b'MZ'
ELF_MAGIC = b'\x7fELF'

def get_fmt(values):
    return '=' + ''.join([v for v in values])

def strcut_unpack(obj, file, keyword):
    fmt = get_fmt(keyword.values())
    byte = file.read(struct.calcsize(fmt))
    data = struct.unpack(fmt, byte)
    i = 0
    for v in keyword.keys():
        setattr(obj, v, data[i])
        i = i + 1

def strcut_pack(obj, keyword):
    fmt = get_fmt(keyword.values())
    data = [getattr(obj, v) for v in keyword.keys()]
    return struct.pack(fmt, *data)

def get_desc(key, desc_table):
    if type(desc_table) == dict:
        key = desc_table[key] if key in desc_table \
            else ' | '.join([desc_table[v] for v in desc_table.keys() if key & v])
    else:
        key = desc_table(key)
    return key

def serialize(obj, keyword, desc):
    res = {}
    for v in keyword.keys():
        attr = getattr(obj, v)
        if v in desc:
            attr = "{0:X} ({1})".format(attr, get_desc(attr, desc[v]))
        else:
            attr = "{0:X}".format(attr)
        res[v] = attr

    return json.dumps(res, indent='    ')

class Magic(Enum):
    PE  = 1
    ELF = 2

class CoffFileHeader:
    _KEYWORD = {
        'Machine':              'H',
        'NumberOfSections':     'H',
        'TimeDateStamp':        'I',
        'PointerToSymbolTable': 'I',
        'NumberOfSymbols':      'I',
        'SizeOfOptionalHeader': 'H',
        'Characteristics':      'H',
    }
    _DESC = {
        'Machine': {
            0x14c:  'x86',
            0x8664: 'x64',
        },
        'TimeDateStamp': lambda x: datetime.datetime.fromtimestamp(x),
        'Characteristics': {
            0x0002: 'Excutable',
            0x0020: 'Application can handle large (>2GB) addresses',
            0x2000: 'DLL',
        },
    }

    def __init__(self, file):
        self._KEYWORD = CoffFileHeader._KEYWORD
        self._DESC    = CoffFileHeader._DESC
        strcut_unpack(self, file, self._KEYWORD)

    def __str__(self):
        return serialize(self, self._KEYWORD, self._DESC)

    def byte(self):
        return strcut_pack(self, self._KEYWORD)

class OptionHeader:
    _KEYWORD = {
        'Magic':                   'H',
        'LinkerVersion':           'H',
        'SizeOfCode':              'I',
        'SizeOfInitializedData':   'I',
        'SizeOfUninitializedData': 'I',
        'AddressOfEntryPoint':     'I',
        'BaseOfCode':              'I',
        'BaseOfData':              'I',

        'ImageBase':               'I',
    }
    _KEYWORD_PLUS = {
        'Magic':                   'H',
        'LinkerVersion':           'H',
        'SizeOfCode':              'I',
        'SizeOfInitializedData':   'I',
        'SizeOfUninitializedData': 'I',
        'AddressOfEntryPoint':     'I',
        'BaseOfCode':              'I',

        'ImageBase':               'L',
    }
    _DESC = {
        'Magic': {
            0x10b: 'PE32',
            0x20b: 'PE32+',
        },
        'LinkerVersion': lambda x: '{0}.{1:0>2d}'.format(x % 0x100, int(x / 0x100)),
    }
    def __init__(self, file):
        self.offset = file.tell()
        magic = int.from_bytes(file.read(2), byteorder=sys.byteorder)
        file.seek(self.offset)

        assert(magic == 0x10b or magic == 0x20b)

        self._KEYWORD = OptionHeader._KEYWORD if magic == 0x10b else OptionHeader._KEYWORD_PLUS
        self._DESC    = OptionHeader._DESC

        strcut_unpack(self, file, self._KEYWORD)

        self._image_type = self._DESC['Magic'][magic]

    def __str__(self):
        return serialize(self, self._KEYWORD, self._DESC)

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
        return json.dumps({
            'FileHeader':   str(self.file_header),
            'OptionHeader': str(self.option_header),
        }, indent='    ')

    def __check_signature(self):
        self._file.seek(0x3c)
        sign_offset = int.from_bytes(self._file.read(4), byteorder=sys.byteorder)

        self._file.seek(sign_offset)
        sign = self._file.read(4)
        assert(sign == b'PE\0\0')

        self.coff_file_header_offset = self._file.tell()

    def __file_header(self):
        self.file_header = CoffFileHeader(self._file)

    def __option_header(self):
        self.option_header = OptionHeader(self._file)

    def __parser(self):
        self.__check_signature()
        self.__file_header()
        self.__option_header()

    def save(self):
        self._file.seek(self.coff_file_header_offset)
        byte = self.file_header.byte()
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
