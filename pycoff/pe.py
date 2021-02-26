import sys
import datetime

from .utility import Header, Version

class Version2(Version):
    def __init__(self, file):
        super(Version2, self).__init__(file, {'Major': '*u1', 'Minor': '*u1',})

class Version4(Version):
    def __init__(self, file):
        super(Version4, self).__init__(file, {'Major': '*u2', 'Minor': '*u2',})

class SectionTable(Header):
    def __init__(self, file):
        super().__init__(desc={
            'Characteristics': {
                0x00000020: 'Code',
                0x00000040: 'Initialized Data',
                0x02000000: 'Discardable',
                0x10000000: 'Shared',
                0x20000000: 'Execute',
                0x40000000: 'Read',
                0x80000000: 'Write',
            },
        })

        self.read('Name',                 file, '*s8')
        self.read('VirtualSize',          file, '*u4')
        self.read('VirtualAddress',       file, '*u4')
        self.read('SizeOfRawData',        file, '*u4')
        self.read('NumberOfSymbols',      file, '*u4')
        self.read('PointerToRawData',     file, '*u4')
        self.read('PointerToRelocations', file, '*u4')
        self.read('NumberOfRelocations',  file, '*u2')
        self.read('NumberOfLinenumbers',  file, '*u2')
        self.read('Characteristics',      file, '*u4')


class FileHeader(Header):
    def __init__(self, file):
        super().__init__(desc={
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
        })
        self._offset = file.tell()

        self.read('Machine',              file, '*u2')
        self.read('NumberOfSections',     file, '*u2')
        self.read('TimeDateStamp',        file, '*u4')
        self.read('PointerToSymbolTable', file, '*u4')
        self.read('NumberOfSymbols',      file, '*u4')
        self.read('SizeOfOptionalHeader', file, '*u2')
        self.read('Characteristics',      file, '*u2')


class DirectoriesHeader(Header):
    def __init__(self, file):
        super().__init__()
        self.read('VirtualAddress', file, '*u4')
        self.read('Size',           file, '*u4')


class OptionHeader(Header):
    def __init__(self, file):
        super().__init__(desc={
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
        })

        self._offset = file.tell()
        magic = int.from_bytes(file.read(2), byteorder=sys.byteorder)
        file.seek(self._offset)

        if magic == 0x10b:
            self._image_type = 'PE32'
        elif magic == 0x20b:
            self._image_type = 'PE32+'
        else:
            assert(False)

        self.read('Magic',                   file, '*u2')
        self.read('LinkerVersion',           file, Version2)
        self.read('SizeOfCode',              file, '*u4')
        self.read('SizeOfInitializedData',   file, '*u4')
        self.read('SizeOfUninitializedData', file, '*u4')
        self.read('AddressOfEntryPoint',     file, '*u4')
        self.read('BaseOfCode',              file, '*u4')

        if magic == 0x10b:
            self.read('BaseOfData',          file, '*u4')
            self.read('ImageBase',           file, '*u4')
        else:
            self.read('ImageBase',           file, '*u8')

        self.read('SectionAlignment',        file, '*u4')
        self.read('FileAlignment',           file, '*u4')
        self.read('OperatingSystemVersion',  file, Version4)
        self.read('ImageVersion',            file, Version4)
        self.read('SubsystemVersion',        file, Version4)
        self.read('Win32VersionValue',       file, '*u4')
        self.read('SizeOfImage',             file, '*u4')
        self.read('SizeOfHeaders',           file, '*u4')
        self.read('CheckSum',                file, '*u4')
        self.read('Subsystem',               file, '*u2')
        self.read('DllCharacteristics',      file, '*u2')

        if magic == 0x10b:
            self.read('SizeOfStackReserve',  file, '*u4')
            self.read('SizeOfStackCommit',   file, '*u4')
            self.read('SizeOfHeapReserve',   file, '*u4')
            self.read('SizeOfHeapCommit',    file, '*u4')
        else:
            self.read('SizeOfStackReserve',  file, '*u8')
            self.read('SizeOfStackCommit',   file, '*u8')
            self.read('SizeOfHeapReserve',   file, '*u8')
            self.read('SizeOfHeapCommit',    file, '*u8')

        self.read('LoaderFlags',             file, '*u4')
        self.read('NumberOfRvaAndSizes',     file, '*u4')

        self.read('ExportTable',           file, DirectoriesHeader)
        self.read('ImportTable',           file, DirectoriesHeader)
        self.read('ResourceTable',         file, DirectoriesHeader)
        self.read('ExceptionTable',        file, DirectoriesHeader)
        self.read('CertificateTable',      file, DirectoriesHeader)
        self.read('BaseRelocationTable',   file, DirectoriesHeader)
        self.read('Debug',                 file, DirectoriesHeader)
        self.read('Architecture',          file, DirectoriesHeader)
        self.read('GlobalPtr',             file, DirectoriesHeader)
        self.read('TLSTable',              file, DirectoriesHeader)
        self.read('LoadConfigTable',       file, DirectoriesHeader)
        self.read('BoundImport',           file, DirectoriesHeader)
        self.read('IAT',                   file, DirectoriesHeader)
        self.read('DelayImportDescriptor', file, DirectoriesHeader)
        self.read('CLRRuntimeHeader',      file, DirectoriesHeader)
        self.read('Reserved',              file, DirectoriesHeader)


class PE(Header):
    def __init__(self, file, path):
        super().__init__(display=['_FileType'])

        self._file = file
        self._path = path
        self._offset  = file.tell()

        self.read('FileHeader', file, FileHeader)
        self.read('OptionHeader', file, OptionHeader)
        self.read('SectionTable', file, [SectionTable for i in range(self.FileHeader.NumberOfSections)])

        if self.FileHeader.Characteristics & 0x2000:
            self._FileType = 'DLL'

    def __def__(self):
        self._file.close()

    def save(self):
        self._file.seek(self._offset)
        byte = to_bytes()
        self._file.write(byte)