import sys
import json
import datetime

from .utility import from_bytes, to_bytes, format

class SectionTable:
    _KEYWORD = {
        'Name':                 's8',
        'VirtualSize':          'u4',
        'VirtualAddress':       'u4',
        'SizeOfRawData':        'u4',
        'PointerToRawData':     'u4',
        'PointerToRelocations': 'u4',
        'PointerToLinenumbers': 'u4',
        'NumberOfRelocations':  'u2',
        'NumberOfLinenumbers':  'u2',
        'Characteristics':      'u4',
    }
    _DESC = {
        'Characteristics': {
            0x00000020: 'Code',
            0x00000040: 'Initialized Data',
            0x02000000: 'Discardable',
            0x10000000: 'Shared',
            0x20000000: 'Execute',
            0x40000000: 'Read',
            0x80000000: 'Write',
        },
    }
    def __init__(self, file):
        self._KEYWORD = SectionTable._KEYWORD
        self._DESC    = SectionTable._DESC

        from_bytes(self, file, self._KEYWORD)

    def __str__(self):
        return str(self.format())
        
    def format(self):
        return format(self, self._KEYWORD, self._DESC)

    def tojson(self, indent='\t'):
        return json.dumps(self.format(), indent=indent)

    def to_bytes(self):
        return to_bytes(self, self._KEYWORD)

class Version:
    def __init__(self, file, keyword, desc):
        self._KEYWORD = keyword
        self._DESC    = desc

        self.Major = 0
        self.Minor = 0

        from_bytes(self, file, keyword)

    def __str__(self):
        return str(self.format())

    def format(self):
        return '{0}.{1:0>2d}'.format(self.Major, self.Minor)

    def tojson(self, indent='\t'):
        return json.dumps(self.format(), indent=indent)

    def to_bytes(self):
        return to_bytes(self, self._KEYWORD)

class Version2(Version):
    _KEYWORD = {
        'Major': 'u1',
        'Minor': 'u1',
    }
    _DESC = {}
    def __init__(self, file):
        super(Version2, self).__init__(file, Version2._KEYWORD, Version2._DESC)

class Version4(Version):
    _KEYWORD = {
        'Major': 'u2',
        'Minor': 'u2',
    }
    _DESC = {}
    def __init__(self, file):
        super(Version4, self).__init__(file, Version4._KEYWORD, Version4._DESC)

class Header:
    def __init__(self, file, keyword, desc):
        self._KEYWORD = keyword
        self._DESC    = desc

        from_bytes(self, file, keyword)

    def __str__(self):
        return str(self.format())
        
    def format(self):
        return format(self, self._KEYWORD, self._DESC)

    def tojson(self, indent='\t'):
        return json.dumps(self.format(), indent=indent)

    def to_bytes(self):
        return to_bytes(self, self._KEYWORD)

class CoffFileHeader(Header):
    _KEYWORD = {
        'Machine':              'u2',
        'NumberOfSections':     'u2',
        'TimeDateStamp':        'u4',
        'PointerToSymbolTable': 'u4',
        'NumberOfSymbols':      'u4',
        'SizeOfOptionalHeader': 'u2',
        'Characteristics':      'u2',
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
        'VirtualAddress':    'u4',
        'Size':              'u4',
    }
    _DESC = {}

    def __init__(self, file):
        super(DirectoriesHeader, self).__init__(file, DirectoriesHeader._KEYWORD, DirectoriesHeader._DESC)

class OptionHeader(Header):
    _KEYWORD_S1 = {
        # Optional Header Standard Fields
        'Magic':                   'u2',
        'LinkerVersion':           Version2,
        'SizeOfCode':              'u4',
        'SizeOfInitializedData':   'u4',
        'SizeOfUninitializedData': 'u4',
        'AddressOfEntryPoint':     'u4',
        'BaseOfCode':              'u4',
    }
    # PE32
    _KEYWORD = {
        'BaseOfData':              'u4',

        # Optional Header Windows-Specific Fields
        'ImageBase':               'u4',
        'SectionAlignment':        'u4',
        'FileAlignment':           'u4',
        'OperatingSystemVersion':  Version4,
        'ImageVersion':            Version4,
        'SubsystemVersion':        Version4,
        'Win32VersionValue':       'u4',
        'SizeOfImage':             'u4',
        'SizeOfHeaders':           'u4',
        'CheckSum':                'u4',
        'Subsystem':               'u2',
        'DllCharacteristics':      'u2',
        'SizeOfStackReserve':      'u4',
        'SizeOfStackCommit':       'u4',
        'SizeOfHeapReserve':       'u4',
        'SizeOfHeapCommit':        'u4',
        'LoaderFlags':             'u4',
        'NumberOfRvaAndSizes':     'u4',
    }

    # PE32+
    _KEYWORD_PLUS = {
        # Optional Header Windows-Specific Fields
        'ImageBase':               'u8',
        'SectionAlignment':        'u4',
        'FileAlignment':           'u4',
        'OperatingSystemVersion':  Version4,
        'ImageVersion':            Version4,
        'SubsystemVersion':        Version4,
        'Win32VersionValue':       'u4',
        'SizeOfImage':             'u4',
        'SizeOfHeaders':           'u4',
        'CheckSum':                'u4',
        'Subsystem':               'u2',
        'DllCharacteristics':      'u2',
        'SizeOfStackReserve':      'u8',
        'SizeOfStackCommit':       'u8',
        'SizeOfHeapReserve':       'u8',
        'SizeOfHeapCommit':        'u8',
        'LoaderFlags':             'u4',
        'NumberOfRvaAndSizes':     'u4',
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
        'Architecture':            DirectoriesHeader,
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
        keyword.update(OptionHeader._KEYWORD if magic == 0x10b else OptionHeader._KEYWORD_PLUS)
        keyword.update(OptionHeader._KEYWORD_S3)

        super(OptionHeader, self).__init__(file, keyword, OptionHeader._DESC)

        self._image_type = self._DESC['Magic'][magic]

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
        self.offset  = file.tell()

        self.__parser()

    def __def__(self):
        self._file.close()

    def __str__(self):
        return str(format(self, self.keyword, self.desc))

    def __parser(self):
        from_bytes(self, self._file, self.keyword)

        keyword = {'SectionTable': [SectionTable for i in range(self.FileHeader.NumberOfSections)]}

        from_bytes(self, self._file, keyword)
        self.keyword.update(keyword)

    def format(self):
        return format(self, self.keyword, self.desc)

    def to_bytes(self):
        return to_bytes(self, self.keyword)

    def tojson(self, indent='\t'):
        return json.dumps(format(self, self.keyword, self.desc), indent=indent)

    def save(self):
        self._file.seek(self.offset)
        byte = to_bytes()
        self._file.write(byte)