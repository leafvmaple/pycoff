import sys

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

def from_bytes(obj, file, keyword):
    for k, v in keyword.items():
        var = parse(obj, file, v)
        setattr(obj, k, var)

def to_bytes(obj, keyword):
    res = b''
    for k, v in keyword.items():
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

def format(obj, keyword, desc):
    res = {}
    for k in keyword.keys():
        value = getattr(obj, k)
        res[k] = format_obj(k, value, desc)

    return res

def read_bytes(file, offset, len):
    cur_offset = file.tell()
    data = file.read(len)
    file.seek(cur_offset)
    return data