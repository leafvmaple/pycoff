import datetime
from .utility import Struct

class ClassID(Struct):
    def __init__(self, file, desc={}, filter=[]):
        super().__init__(desc=desc, filter=filter)
        self.read('ID', file, ['*u4', '*u2', '*u2', '+u2', '+u6'])

    def format(self):
        return '{{{0:08X}-{1:X}-{2:X}-{3:X}-{4:X}}}'.format(self.ID[0], self.ID[1], self.ID[2], self.ID[3], self.ID[4])

class CoffHeader(Struct):
    def __init__(self, file, desc={}, filter=[]):
        desc.update({
            'Machine': {
                0x14c:  'x86',
                0x8664: 'x64',
            },
            # 'TimeDateStamp': lambda x: datetime.datetime.fromtimestamp(x),
        })
        super().__init__(desc=desc, filter=filter)

        self.read('Version',       file, '*u2')
        self.read('Machine',       file, '*u2')
        self.read('TimeDateStamp', file, '*u4')

        if self.Version == 0:
            self.read('SizeOfData',    file, '*u4')
            self.read('Hint',          file, '*u2')
        elif self.Version == 1:
            self.read('ClassID',       file,  ClassID)
            self.read('SizeOfData',    file, '*u4')
            # self.read('Hint',          file, '*u2')
            # self.read('Flag',          file, '-u1')


class COFF(Struct):
    def __init__(self, file, file_path, desc={}, filter=[]):
        super().__init__()
        self.read('Coff', file, CoffHeader)