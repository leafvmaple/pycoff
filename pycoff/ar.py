import datetime
from .utility import Header, Version

class MemberHeader(Header):
    _EXPORT = {
        'Name':              's16',
        'Date':              's12',
        'UserID':            's6',
        'GroupID':           's6',
        'Mode':              's8',
        'Size':              's10',
        'EndOfHeader':       's2',
    }
    _DESC = {
        'Date': lambda x: datetime.datetime.fromtimestamp(int(x)),
    }

    def __init__(self, file):
        super().__init__(desc=MemberHeader._DESC)
        self.update(file, MemberHeader._EXPORT)
        
        assert(self.EndOfHeader == '`\n')

class AR(Header):
    _EXPORT = {
        'MemberHeader':   MemberHeader,
    }
    def __init__(self, file, path):
        self._file = file
        self._path = path

        super().__init__()
        self.update(file, AR._EXPORT)
