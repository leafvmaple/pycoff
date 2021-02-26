import sys
import json

from .defs import MAGIC, COFF_TYPE

BYTE_ORDER = {
    '*': sys.byteorder,
    '+': 'big',
    '-': 'little',
}

def read_string(file, byteorder, len):
    if len <= 0:
        res = []
        ch = file.read(1)
        while (ch != b'\0'):
            res.append(ch)
            ch = file.read(1)
        res = b''.join(res)
    else:
        res = file.read(int(len))
    return bytes.decode(res.strip(b'\0 '), errors="strict")


READ_BYTE = {
    'u': lambda f, o, x: int.from_bytes(f.read(int(x)), o),
    'i': lambda f, o, x: int.from_bytes(f.read(int(x)), o, signed=True),
    's': lambda f, o, x: read_string(f, o, int(x)),
}

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

    # AR
    file.seek(0)
    magic = file.read(len(MAGIC.AR))
    if magic == MAGIC.AR:
        return COFF_TYPE.AR

def read(file, form):
    if type(form) == str:
        var = READ_BYTE[form[1]](file, BYTE_ORDER[form[0]], form[2:])
    elif type(form) == type:
        var = form(file)
    elif type(form) == list:
        var = [read(file, v) for v in form]
    return var

def from_bytes(obj, file, export):
    for k, v in export.items():
        var = read(file, v)
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
    return "{0}".format(value)

def format_obj(key, value, desc):
    if key in desc:
        res = format_desc(value, desc[key])
    elif type(value) == int:
        res = "{0:X}".format(value)
    elif type(value) == str:
        res = value
    elif type(value) == list:
        res = [format_obj(key, v, desc) for v in value]
    else:
        res = value.format()
    
    return res

def format(obj, keys, desc):
    res = {}
    for k in keys:
        value = getattr(obj, k)
        res[k] = format_obj(k, value, desc)

    return res

def read_bytes(file, offset, len):
    cur_offset = file.tell()
    data = file.read(len)
    file.seek(cur_offset)
    return data


class Header:
    def __init__(self, desc={}, display=[], filter=[]):
        self._form    = {}
        self._export  = {}
        self._desc    = desc
        self._display = display
        self._filter  = filter

    def __str__(self):
        return str(self.format())
        
    def format(self):
        keys = [v for v in vars(self).keys() if (not v.startswith('_') or v in self._display) and v not in self._filter]
        return format(self, keys, self._desc)
        # return format(self, list(set(vars(self).keys()).union(set(self._display)).difference(set(self._filter))), self._desc)

    def read(self, key, file, form):
        self._form[key] = form
        setattr(self, key, read(file, form))

    def tojson(self, indent='\t'):
        return json.dumps(self.format(), indent=indent)

    def to_bytes(self):
        return to_bytes(self, self._export)

class Version:
    def __init__(self, file, export):
        self._export = export

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
        return to_bytes(self, self._export)
