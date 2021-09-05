import datetime
from .utility import Struct

class ObjHeader(Struct):
    def __init__(self, file, desc={}, filter=[]):
        desc.update({
            'Machine': {
                0x14c:  'x86',
                0x8664: 'x64',
            },
            'TimeDateStamp': lambda x: datetime.datetime.fromtimestamp(x),
        })
        super().__init__(desc=desc, filter=filter)

        self.read('Machine',       file, '*u2')
        self.read('NumberOfSections',     file, '*u2')
        self.read('TimeDateStamp',        file, '*u4')

class OBJ(Struct):
    def __init__(self, file, file_path, desc={}, filter=[]):
        super().__init__()
        self.read('Header', file, ObjHeader)