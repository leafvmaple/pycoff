import datetime
from .utility import Header, Version

def read_header(self, file):
    self._offset = file.tell()

    self.read('Name',        file, '*s16')
    self.read('Date',        file, '*s12')
    self.read('UserID',      file, '*s6' )
    self.read('GroupID',     file, '*s6' )
    self.read('Mode',        file, '*s8' )
    self.read('Size',        file, '*s10')
    self.read('EndOfHeader', file, '*s2' )

    assert(self.EndOfHeader == '`\n')
    
    self._filter.append('EndOfHeader')


class FirstLinkerMember(Header):
    def __init__(self, file):
        super().__init__(desc={
            'Date': lambda x: datetime.datetime.fromtimestamp(int(x)),
        }, filter=[
            'Offset', 'StringTable'
        ])

        read_header(self, file)

        self.read('NumberOfSymbols', file, '+u4')
        self.read('Offset', file, ['+u4' for i in range(self.NumberOfSymbols)])
        self.read('StringTable', file, ['*s0' for i in range(self.NumberOfSymbols)])


    def format(self):
        data = super().format()
        data['Symbols'] = ['{0:X} {1}'.format(self.Offset[i], self.StringTable[i]) for i in range(self.NumberOfSymbols)]
        return data


class SecondLinkerMember(Header):
    def __init__(self, file):
        super().__init__(desc={
            'Date': lambda x: datetime.datetime.fromtimestamp(int(x)),
        }, filter=[
            'Indices', 'StringTable'
        ])

        read_header(self, file)

        self.read('NumberOfMembers', file, '*u4')
        self.read('Offset', file, ['*u4' for i in range(self.NumberOfMembers)])
        self.read('NumberOfSymbols', file, '*u4')
        self.read('Indices', file, ['*u2' for i in range(self.NumberOfSymbols)])
        self.read('StringTable', file, ['*s0' for i in range(self.NumberOfSymbols)])

    def format(self):
        data = super().format()
        data['Symbols'] = ['{0:X} {1}'.format(self.Indices[i], self.StringTable[i]) for i in range(self.NumberOfSymbols)]
        return data


class LongnamesMember(Header):
    def __init__(self, file):
        super().__init__(desc={
            'Date': lambda x: datetime.datetime.fromtimestamp(int(x)),
        })

        read_header(self, file)


class AR(Header):
    def __init__(self, file, path):
        super().__init__()

        self._file = file
        self._path = path

        self.read('FirstLinkerMember', file, FirstLinkerMember)
        self.read('SecondLinkerMember', file, SecondLinkerMember)
        self.read('LongnamesMember', file, LongnamesMember)
        self.read('ObjectsMember', file, ['*s0' for i in range(self.SecondLinkerMember.NumberOfMembers)])
