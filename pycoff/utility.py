import sys
import json

from .defs import MAGIC, COFF_TYPE, READ_BYTE

def check_pe(file):
    file.seek(0x3c)
    sign_offset = int.from_bytes(file.read(4), byteorder=sys.byteorder)
    if sign_offset <= 0:
        return False

    file.seek(sign_offset)
    magic = file.read(len(MAGIC.PE))
    return magic == MAGIC.PE

def check_magic(file):
    # ELF
    magic = file.read(len(MAGIC.ELF))
    if magic == MAGIC.ELF:
        return COFF_TYPE.ELF

    # PE / MZ
    file.seek(0)
    magic = file.read(len(MAGIC.MZ))
    if magic == MAGIC.MZ:
        return COFF_TYPE.PE if check_pe(file) else COFF_TYPE.MZ

def parse(obj, file, types):
    if type(types) == str:
        var = READ_BYTE[types[0]](file, int(types[1]))
    elif type(types) == type:
        var = types(file)
    elif type(types) == list:
        var = [parse(obj, file, v) for v in types]
    return var

def from_bytes(obj, file, export):
    for k, v in export.items():
        var = parse(obj, file, v)
        setattr(obj, k, var)

def to_bytes(obj, export):
    res = b''
    for k, v in export.items():
        if hasattr(obj, k):
            value = getattr(obj, k)
            if type(v) == int:
                res = res + value.to_bytes(v, byteorder=sys.byteorder)
            elif type(v) == type:
                res = res + value.to_bytes()

    return res

def format_desc(value, desc):
    if type(desc) == dict:
        value = desc[value] if value in desc \
            else ' | '.join([desc[v] for v in desc.keys() if value & v])
    else:
        value = desc(value)
    return " ({0})".format(value)

def format_obj(key, value, desc):
    if type(value) == int:
        res = "{0:X}".format(value)
    elif type(value) == str:
        res = value
    elif type(value) == list:
        res = [format_obj(key, v, desc) for v in value]
    else:
        res = value.format()
    if key in desc:
        res = res + format_desc(value, desc[key])
    return res

def format(obj, display, desc):
    res = {}
    for k in display:
        if hasattr(obj, k):
            value = getattr(obj, k)
            res[k] = format_obj(k, value, desc)

    return res

def read_bytes(file, offset, len):
    cur_offset = file.tell()
    data = file.read(len)
    file.seek(cur_offset)
    return data


class Header:
    def __init__(self, desc={}, display=[]):
        self.export  = {}
        self.desc    = desc
        self.display = display

    def __str__(self):
        return str(self.format())
        
    def update(self, file, export):
        from_bytes(self, file, export)

        self.export.update(export)
        self.display = self.display + list(export.keys())
        
    def format(self):
        return format(self, self.display, self.desc)

    def tojson(self, indent='\t'):
        return json.dumps(self.format(), indent=indent)

    def to_bytes(self):
        return to_bytes(self, self.export)

class Version:
    def __init__(self, file, export):
        self.export = export

        self.Major = 0
        self.Minor = 0

        from_bytes(self, file, export)

    def __str__(self):
        return str(self.format())

    def format(self):
        return '{0}.{1:0>2d}'.format(self.Major, self.Minor)

    def tojson(self, indent='\t'):
        return json.dumps(self.format(), indent=indent)

    def to_bytes(self):
        return to_bytes(self, self.export)