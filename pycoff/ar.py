import datetime
import sys
from .coff import CoffHeader
from .utility import Struct, get_null_string

def read_archive_header(self, file):
    self._desc.update({
        'Date': lambda x: datetime.datetime.fromtimestamp(x) if x > 0 else 'FFFFFFFF',
        'Mode': {
            0x0040: 'IEXEC',
            0x0080: 'IWRITE',
            0x0100: 'IREAD',
            0x1000: 'IFIFO',
            0x4000: 'IFDIR',
            0x8000: 'IFREG',
        },
    })
    self._filter.extend([
        'EndOfHeader'
    ])

    self._offset = file.tell()
    if file.read(1) != b'\n':
        file.seek(self._offset)

    self.read('Name',        file, '*s16')
    self.read('Date',        file, 'is12')
    self.read('UserID',      file, '*s6' )
    self.read('GroupID',     file, '*s6' )
    self.read('Mode',        file, 'is8' )
    self.read('Size',        file, 'is10')
    self.read('EndOfHeader', file, '*s2' )

    assert(self.EndOfHeader == '`\n')

def read_import_header(self, file):
    self._desc.update({
        'Machine': {
            0x14c:  'x86',
            0x8664: 'x64',
        },
        'TimeDateStamp': lambda x: datetime.datetime.fromtimestamp(x),
    })

    self.read('Version',       file, '*u2')
    self.read('Machine',       file, '*u2')
    self.read('TimeDateStamp', file, '*u4')
    
    '''self.read('SizeOfData',    file, '*u4')
    self.read('Ordinal',       file, '*u2')

    print(file.read(1))
    
    raw = int.from_bytes(file.read(2), 'little')
    print('{0:b}'.format(raw))

    self.Type = raw >> 13
    self.NameType = (raw >> 10) & 0b111

    print(file.read(20))'''


class ArchiveHeader(Struct):
    def __init__(self, file, desc={}, filter=[]):
        desc.update({
            'Date': lambda x: datetime.datetime.fromtimestamp(x),
            'Mode': {
                0x0040: 'IEXEC',
                0x0080: 'IWRITE',
                0x0100: 'IREAD',
                0x1000: 'IFIFO',
                0x4000: 'IFDIR',
                0x8000: 'IFREG',
            },
        })
        filter.extend([
            'EndOfHeader'
        ])
        super().__init__(desc=desc, filter=filter)

        self._offset = file.tell()
        if file.read(1) != b'\n':
            file.seek(self._offset)

        self.read('Name',        file, '*s16')
        self.read('Date',        file, 'is12')
        self.read('UserID',      file, '*s6' )
        self.read('GroupID',     file, '*s6' )
        self.read('Mode',        file, 'is8' )
        self.read('Size',        file, 'is10')
        self.read('EndOfHeader', file, '*s2' )

        assert(self.EndOfHeader == '`\n')


class FirstLinkerHeader(Struct):
    def __init__(self, file):
        super().__init__( filter=[
            'Offset', 'StringTable'
        ])

        read_archive_header(self, file)

        self.read('NumberOfSymbols', file, '+u4')
        self.read('Offset', file, ['+u4' for i in range(self.NumberOfSymbols)])
        self.read('StringTable', file, ['*s0' for i in range(self.NumberOfSymbols)])

        self._export_list = []
        for i in range(self.NumberOfSymbols):
            if not self.StringTable[i].startswith('_'):
                self._export_list.append(self.StringTable[i])


class SecondLinkerHeader(Struct):
    def __init__(self, file):
        super().__init__(filter=[
            'Offset', 'Indices', 'StringTable'
        ])

        read_archive_header(self, file)

        self.read('NumberOfMembers', file, '*u4')
        self.read('Offset', file, ['*u4' for i in range(self.NumberOfMembers)])
        self.read('NumberOfSymbols', file, '*u4')
        self.read('Indices', file, ['*u2' for i in range(self.NumberOfSymbols)])
        self.read('StringTable', file, ['*s0' for i in range(self.NumberOfSymbols)])

        self._indeces_map = {}
        for i in range(self.NumberOfSymbols):
            self._indeces_map.setdefault(self.Indices[i], []).append(self.StringTable[i])


class LongnamesHeader(Struct):
    def __init__(self, file):
        super().__init__()

        read_archive_header(self, file)

        self._data = file.read(self.Size)


class ObjectFileHeader(Struct):
    def __init__(self, file):
        super().__init__(desc={
            'Name': lambda x: self._real_name
        })

        self._real_name = ''

        read_archive_header(self, file)
        self._content_offset = file.tell()

        magic = file.read(4)
        if magic == b'\0\0\xFF\xFF':
            self.read('Cotent', file, CoffHeader)

        file.seek(self._content_offset + self.Size)

    def update_name(self, data):
        if self.Name.startswith('/'):
            self._real_name = get_null_string(data, int(self.Name[1:]))

    def update_symbos(self, addr, indeces):
        self.Addr = addr
        self.Symbols = indeces


class AR(Struct):
    def __init__(self, file, path):
        super().__init__()

        self._file = file
        self._path = path

        self.read('FirstLinker', file, FirstLinkerHeader)
        self.read('SecondLinker', file, SecondLinkerHeader)
        self.read('_Longnames', file, LongnamesHeader)
        self.read('ObjectFiles', file, [ObjectFileHeader for i in range(self.SecondLinker.NumberOfMembers)])

        for i in range(len(self.ObjectFiles)):
            self.ObjectFiles[i].update_name(self._Longnames._data)
            # self.ObjectFiles[i].update_symbos(self.SecondLinker.Offset[i], self.SecondLinker._indeces_map[i + 1])

        # print(file.read(128))