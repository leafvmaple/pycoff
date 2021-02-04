#!/usr/bin/python
from enum import Enum
import sys
import datetime
import json

class COFF_TYPE(Enum):
    PE  = 1
    ELF = 2

MAGIC = {
    COFF_TYPE.PE:  b'MZ',
    COFF_TYPE.ELF: b'\x7fELF',
}

def frombytes(obj, file, keyword):
    for k, v in keyword.items():
        if type(v) == int:
            var = int.from_bytes(file.read(v), byteorder=sys.byteorder)
        elif type(v) == type:
            var = v(file)
        setattr(obj, k, var)

def tobytes(obj, keyword):
    res = b''
    for k, v in keyword.items():
        att = getattr(obj, k)
        if type(v) == int:
            res = res + att.to_bytes(v, byteorder=sys.byteorder)
        elif type(v) == type:
            res = res + att.to_bytes()

    return res

def format_desc(key, desc):
    if type(desc) == dict:
        key = desc[key] if key in desc \
            else ' | '.join([desc[v] for v in desc.keys() if key & v])
    else:
        key = desc(key)
    return " ({0})".format(key)

def format(obj, keyword, desc):
    res = {}
    for k in keyword.keys():
        attr = getattr(obj, k)
        if type(attr) == int:
            string = "{0:X}".format(attr)
        else:
            string = attr.format()
        if k in desc:
            string = string + format_desc(attr, desc[k])
        res[k] = string

    return res

class Version:
    def __init__(self, file, keyword, desc):
        self._KEYWORD = keyword
        self._DESC    = desc

        self.Major = 0
        self.Minor = 0

        frombytes(self, file, keyword)

    def __str__(self):
        return str(self.format(), self._DESC)

    def format(self):
        return '{0}.{1:0>2d}'.format(self.Major, self.Minor)

    def tojson(self, indent='\t'):
        return json.dumps(self.format(), indent=indent)

    def tobytes(self):
        return tobytes(self, self._KEYWORD)

class Version2(Version):
    _KEYWORD = {
        'Major': 1,
        'Minor': 1,
    }
    _DESC = {}
    def __init__(self, file):
        super(Version2, self).__init__(file, Version2._KEYWORD, Version2._DESC)

class Version4(Version):
    _KEYWORD = {
        'Major': 2,
        'Minor': 2,
    }
    _DESC = {}
    def __init__(self, file):
        super(Version4, self).__init__(file, Version4._KEYWORD, Version4._DESC)

class Header:
    def __init__(self, file, keyword, desc):
        self._KEYWORD = keyword
        self._DESC    = desc

        frombytes(self, file, keyword)

    def __str__(self):
        return str(self.format())
        
    def format(self):
        return format(self, self._KEYWORD, self._DESC)

    def tojson(self, indent='\t'):
        return json.dumps(self.format(), indent=indent)

    def tobytes(self):
        return tobytes(self, self._KEYWORD)

class CoffFileHeader(Header):
    _KEYWORD = {
        'Machine':              2,
        'NumberOfSections':     2,
        'TimeDateStamp':        4,
        'PointerToSymbolTable': 4,
        'NumberOfSymbols':      4,
        'SizeOfOptionalHeader': 2,
        'Characteristics':      2,
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
        self.offset = file.tell()
        super(CoffFileHeader, self).__init__(file, CoffFileHeader._KEYWORD, CoffFileHeader._DESC)

class DirectoriesHeader(Header):
    _KEYWORD = {
        'VirtualAddress':    4,
        'Size':              4,
    }
    _DESC = {}

    def __init__(self, file):
        super(DirectoriesHeader, self).__init__(file, DirectoriesHeader._KEYWORD, DirectoriesHeader._DESC)

class OptionHeader(Header):
    _KEYWORD_S1 = {
        # Optional Header Standard Fields
        'Magic':                   2,
        'LinkerVersion':           Version2,
        'SizeOfCode':              4,
        'SizeOfInitializedData':   4,
        'SizeOfUninitializedData': 4,
        'AddressOfEntryPoint':     4,
        'BaseOfCode':              4,
    }
    # PE32
    _KEYWORD = {
        'BaseOfData':              4,

        # Optional Header Windows-Specific Fields
        'ImageBase':               4,
        'SectionAlignment':        4,
        'FileAlignment':           4,
        'OperatingSystemVersion':  Version4,
        'ImageVersion':            Version4,
        'SubsystemVersion':        Version4,
        'Win32VersionValue':       4,
        'SizeOfImage':             4,
        'SizeOfHeaders':           4,
        'CheckSum':                4,
        'Subsystem':               2,
        'DllCharacteristics':      2,
        'SizeOfStackReserve':      4,
        'SizeOfStackCommit':       4,
        'SizeOfHeapReserve':       4,
        'SizeOfHeapCommit':        4,
        'LoaderFlags':             4,
        'NumberOfRvaAndSizes':     4,
    }

    # PE32+
    _KEYWORD_PLUS = {
        # Optional Header Windows-Specific Fields
        'ImageBase':               8,
        'SectionAlignment':        4,
        'FileAlignment':           4,
        'OperatingSystemVersion':  Version4,
        'ImageVersion':            Version4,
        'SubsystemVersion':        Version4,
        'Win32VersionValue':       4,
        'SizeOfImage':             4,
        'SizeOfHeaders':           4,
        'CheckSum':                4,
        'Subsystem':               2,
        'DllCharacteristics':      2,
        'SizeOfStackReserve':      8,
        'SizeOfStackCommit':       8,
        'SizeOfHeapReserve':       8,
        'SizeOfHeapCommit':        8,
        'LoaderFlags':             4,
        'NumberOfRvaAndSizes':     4,
    }

    _KEYWORD_S3 = {
        # Optional Header Data Directories
        'ExportTable':             DirectoriesHeader,
        'ImportTable':             DirectoriesHeader,
        'ResourceTable':           DirectoriesHeader,
        'ExceptionTable':          DirectoriesHeader,
        'CertificateTable':        DirectoriesHeader,
        'BaseRelocationTable':     DirectoriesHeader,
        'Debug':                   DirectoriesHeader,
        'GlobalPtr':               DirectoriesHeader,
        'TLSTable':                DirectoriesHeader,
        'LoadConfigTable':         DirectoriesHeader,
        'BoundImport':             DirectoriesHeader,
        'IAT':                     DirectoriesHeader,
        'DelayImportDescriptor':   DirectoriesHeader,
        'CLRRuntimeHeader':        DirectoriesHeader,
        'Reserved':                DirectoriesHeader,
    }

    _DESC = {
        'Magic': {
            0x10b: 'PE32',
            0x20b: 'PE32+',
        },

        'Subsystem': {
            2: 'Windows GUI',
        },
        'DllCharacteristics': {
            0x20:  'High Entropy Virtual Addresses',
            0x40:  'Dynamic base',
            0x100: 'NX compatible'
        },
    }
    def __init__(self, file):
        self.offset = file.tell()
        magic = int.from_bytes(file.read(2), byteorder=sys.byteorder)
        file.seek(self.offset)

        assert(magic == 0x10b or magic == 0x20b)

        keyword = OptionHeader._KEYWORD_S1
        keyword.update(ptionHeader._KEYWORD if magic == 0x10b else OptionHeader._KEYWORD_PLUS)
        keyword.update(OptionHeader._KEYWORD_S3)

        super(OptionHeader, self).__init__(file, keyword, OptionHeader._DESC)

        self._image_type = self._DESC['Magic'][magic]


class ELF:
    def __init__(self, file, path):
        self._file = file
        self._path = path


class PE:
    _KEYWORD = {
        'FileHeader':   CoffFileHeader,
        'OptionHeader': OptionHeader,
    }

    def __init__(self, file, path):
        self._file = file
        self._path = path

        self.keyword = PE._KEYWORD
        self.desc    = {}

        self.__parser()

    def __def__(self):
        self._file.close()

    def __str__(self):
        return str(format(self, self.keyword, self.desc))

    def __check_signature(self):
        self._file.seek(0x3c)
        sign_offset = int.from_bytes(self._file.read(4), byteorder=sys.byteorder)

        self._file.seek(sign_offset)
        sign = self._file.read(4)
        assert(sign == b'PE\0\0')

        self.byte_offset = self._file.tell()

    def __parser(self):
        self.__check_signature()
        
        frombytes(self, self._file, self.keyword)

    def format(self):
        return format(self, self.keyword, self.desc)

    def tobytes(self):
        return tobytes(self, self.keyword)

    def tojson(self, indent='\t'):
        return json.dumps(format(self, self.keyword, self.desc), indent=indent)

    def save(self):
        self._file.seek(self.byte_offset)
        byte = tobytes()
        self._file.write(byte)

def check_magic(file):
    for k, v in MAGIC.items():
        file.seek(0)
        magic = file.read(len(v))
        if magic == v:
            return k

def parser(file_path):
    file = open(file_path, 'rb+')
    coff_type = check_magic(file)

    if coff_type == COFF_TYPE.PE:
        return PE(file, file_path)
    elif coff_type == COFF_TYPE.ELF:
        return ELF(file, file_path)
