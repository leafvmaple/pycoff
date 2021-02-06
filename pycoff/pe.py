import sys
import datetime

from .utility import Header, Version

class Version2(Version):
    _EXPORT = {
        'Major': 'u1',
        'Minor': 'u1',
    }
    def __init__(self, file):
        super(Version2, self).__init__(file, Version2._EXPORT)

class Version4(Version):
    _EXPORT = {
        'Major': 'u2',
        'Minor': 'u2',
    }
    def __init__(self, file):
        super(Version4, self).__init__(file, Version4._EXPORT)

class SectionTable(Header):
    _EXPORT = {
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
        super().__init__(SectionTable._DESC)
        self.update(file, SectionTable._EXPORT)

class CoffFileHeader(Header):
    _EXPORT = {
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
        super().__init__(CoffFileHeader._DESC)
        self.offset = file.tell()

        self.update(file, CoffFileHeader._EXPORT)

class DirectoriesHeader(Header):
    _EXPORT = {
        'VirtualAddress':    'u4',
        'Size':              'u4',
    }

    def __init__(self, file):
        super().__init__()
        self.update(file, DirectoriesHeader._EXPORT)

class OptionHeader(Header):
    _EXPORT_S1 = {
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
    _EXPORT = {
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
    _EXPORT_PLUS = {
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

    _EXPORT_S3 = {
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
        super().__init__(OptionHeader._DESC)
        self.offset = file.tell()

        magic = int.from_bytes(file.read(2), byteorder=sys.byteorder)
        file.seek(self.offset)

        assert(magic == 0x10b or magic == 0x20b)

        self.update(file, OptionHeader._EXPORT_S1)
        if magic == 0x10b:
            self.update(file, OptionHeader._EXPORT)
        else:
            self.update(file, OptionHeader._EXPORT_PLUS)
        self.update(file, OptionHeader._EXPORT_S3)

        self._image_type = self._DESC['Magic'][magic]

class PE(Header):
    _EXPORT = {
        'FileHeader':   CoffFileHeader,
        'OptionHeader': OptionHeader,
    }
    _DISPLAY = ['FileType']

    def __init__(self, file, path):
        self._file = file
        self._path = path
        super().__init__(display=PE._DISPLAY)

        self.offset  = file.tell()

        self.update(file, PE._EXPORT)

        export = {'SectionTable': [SectionTable for i in range(self.FileHeader.NumberOfSections)]}
        self.update(file, export)

        if self.FileHeader.Characteristics & 0x2000:
            self.FileType = 'DLL'

    def __def__(self):
        self._file.close()

    def save(self):
        self._file.seek(self.offset)
        byte = to_bytes()
        self._file.write(byte)