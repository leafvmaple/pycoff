import datetime
from .utility import Header

class ArchiveHeader(Header):
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


class FirstLinkerHeader(ArchiveHeader):
    def __init__(self, file):
        super().__init__(file, filter=[
            'Offset', 'StringTable'
        ])

        self.read('NumberOfSymbols', file, '+u4')
        self.read('Offset', file, ['+u4' for i in range(self.NumberOfSymbols)])
        self.read('StringTable', file, ['*s0' for i in range(self.NumberOfSymbols)])


class SecondLinkerHeader(ArchiveHeader):
    def __init__(self, file):
        super().__init__(file, filter=[
            'Offset', 'Indices', 'StringTable'
        ])

        self.read('NumberOfMembers', file, '*u4')
        self.read('Offset', file, ['*u4' for i in range(self.NumberOfMembers)])
        self.read('NumberOfSymbols', file, '*u4')
        self.read('Indices', file, ['*u2' for i in range(self.NumberOfSymbols)])
        self.read('StringTable', file, ['*s0' for i in range(self.NumberOfSymbols)])

        self._indeces_map = {}
        for i in range(self.NumberOfSymbols):
            self._indeces_map.setdefault(self.Indices[i], []).append(self.StringTable[i])


class LongnamesHeader(ArchiveHeader):
    def __init__(self, file):
        super().__init__(file)

        self._data = file.read(self.Size)


class ObjectFileHeader(ArchiveHeader):
    def __init__(self, file):
        super().__init__(file, desc={
            'Name': lambda x: self._real_name
        })

        self._content_offset = file.tell()
        file.seek(self._content_offset + self.Size)


    def update_name(self, data):
        if self.Name.startswith('/'):
            idx = int(self.Name[1:])
            name = []
            while data[idx] != 0:
                name.append(chr(data[idx]))
                idx = idx + 1
            self._real_name = ''.join(name)

    def update_symbos(self, addr, indeces):
        self.Addr = addr
        self.Symbols = indeces


class AR(Header):
    def __init__(self, file, path):
        super().__init__()

        self._file = file
        self._path = path

        self.read('FirstLinker', file, FirstLinkerHeader)
        self.read('SecondLinker', file, SecondLinkerHeader)
        self.read('_Longnames', file, LongnamesHeader)
        self.read('ObjectFiles', file, [ObjectFileHeader for i in range(self.SecondLinker.NumberOfMembers)])

        for i in range(self.SecondLinker.NumberOfMembers):
            self.ObjectFiles[i].update_name(self._Longnames._data)
            self.ObjectFiles[i].update_symbos(self.SecondLinker.Offset[i], self.SecondLinker._indeces_map[i + 1])