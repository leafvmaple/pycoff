from .utility import Struct, get_null_string

class Section(Struct):
    def __init__(self, file, initvars):
        super().__init__(initvars=initvars)

        self._data = file.read(self.Size)
        self._contents = bytes.decode(self._data.strip(b'\0 ')) if self.Flags & 0x020 else ' '.join(['%02X' % b for b in self._data])
    
    def format(self):
        return self._contents

class FileHeader(Struct):
    def __init__(self, file):
        super().__init__(desc={
            'EI_Class': {
                0x01: 'ELF32',
                0x02: 'ELF64',
            },
            'EI_Data': {
                1: 'Little Endian',
                2: 'Big Endian',
            },
            'EI_OSABI': {
                0x00: 'System V',
                0x01: 'HP-UX',
                0x02: 'NetBSD',
                0x03: 'Linux',
            },
            'Type': {
                0x00: 'NONE',
                0x01: 'REL',
                0x02: 'EXEC',
                0x03: 'DYN (Shared Object File)'
            },
            'Machine': {
                0x01: 'AT&T WE 32100',
                0x02: 'SPARC',
                0x03: 'X86',
                0x04: 'M68k',
                0x05: 'M88k',
                0x06: 'Intel MCU',
                0x3E: 'AMD64'
            },
        })

        self.read('EI_Class',      file, '*u1')
        self._Class = 'x86' if self.EI_Class == 1 else 'x64'

        self.read('EI_Data',       file, '*u1')
        self.read('EI_Version',    file, '*u1')
        self.read('EI_OSABI',      file, '*u1')
        self.read('EI_ABIVersion', file, '*u1')

        file.seek(file.tell() + 7)

        self.read('Type',    file, '*u2')
        self.read('Machine', file, '*u2')
        self.read('Version', file, '*u4')
        
        if self._Class == 'x86':
            self.read('Entry', file, '*u4')
            self.read('ProgramHeaderOffset', file, '*u4')
            self.read('SectionHeaderOffset', file, '*u4')
        else:
            self.read('Entry', file, '*u8')
            self.read('ProgramHeaderOffset', file, '*u8')
            self.read('SectionHeaderOffset', file, '*u8')

        self.read('Flags',               file, '*u4')
        self.read('FileHeaderSize',      file, '*u2')
        self.read('ProgramHeaderSize',   file, '*u2')
        self.read('ProgramHeaderNum',    file, '*u2')
        self.read('SectionHeaderSize',   file, '*u2')
        self.read('SectionHeaderNum',    file, '*u2')
        self.read('StringTableIndex',      file, '*u2')


class ProgramHeader(Struct):
    def __init__(self, file, initvars):
        super().__init__(desc={
            'Type': {
                0x00000001: 'LOAD',
                0x00000002: 'DYNAMIC',
                0x00000003: 'INTERP',
                0x00000004: 'NOTE',
                0x00000006: 'PHDR',
                0x6474E550: 'GNU_EH_FRAME',
                0x6474E551: 'GNU_STACK',
                0x6474E552: 'GNU_RELRO',
                0x6474E553: 'GNU_PROPERTY',
            },
        }, initvars=initvars)

        self.read('Type',    file, '*u4')

        if self._Class == 'x86':
            self.read('Offset',  file, '*u4')
            self.read('VAddr',   file, '*u4')
            self.read('PAddr',   file, '*u4')
            self.read('Filesz',  file, '*u4')
            self.read('Memsz',   file, '*u4')
            self.read('Filesz',  file, '*u4')
            self.read('Flags',   file, '*u4')
            self.read('Align',   file, '*u4')
        else:
            self.read('Flags',   file, '*u4')
            self.read('Offset',  file, '*u8')
            self.read('VAddr',   file, '*u8')
            self.read('PAddr',   file, '*u8')
            self.read('Filesz',  file, '*u8')
            self.read('Memsz',   file, '*u8')
            self.read('Align',   file, '*u8')


class SectionHeader(Struct):
    def __init__(self, file, initvars):
        super().__init__(desc={
            'Type': {
                0x00: 'NULL',
                0x01: 'PROGBITS',
                0x02: 'SYMTAB',
                0x03: 'STRTAB',
                0x04: 'RELA',
                0x05: 'HASH',
                0x006: 'PHDR',
                0x07: 'NOTE',
                0x08: 'NOBITS',
                0x09: 'REL',
                0x0A: 'SHLIB',
                0x0B: 'DYNSYM',
                0x0E: 'INIT_ARRAY',
                0x0F: 'FINI_ARRAY',
                0x10: 'PREINIT_ARRAY',
                0x11: 'GROUP',
                0x12: 'SYMTAB_SHNDX',
                0x13: 'NUM',
                
                0x6FFFFFF6: 'GNU_HASH',
                0x6FFFFFFE: 'GNU_VERNEED',
                0x6FFFFFFF: 'GNU_VERSYM',
            },
            'Flags': {
                0x001: 'WRITE',
                0x002: 'ALLOC',
                0x004: 'EXECINSTR',
                0x010: 'MERGE',
                0x020: 'STRINGS',
                0x040: 'INFO_LINK',
                0x080: 'LINK_ORDER',
                0x100: 'OS_NONCONFORMING',
            },
        }, initvars=initvars)

        self.read('Name',    file, '*u4')
        self.read('Type',    file, '*u4')

        if self._Class == 'x86':
            self.read('Flags',       file, '*u4')
            self.read('Addr',        file, '*u4')
            self.read('Offset',      file, '*u4')
            self.read('Size',        file, '*u4')
            self.read('Link',        file, '*u4')
            self.read('Info',        file, '*u4')
            self.read('AddrAlign',   file, '*u4')
            self.read('EntSize',     file, '*u4')
        else:
            self.read('Flags',       file, '*u8')
            self.read('Addr',        file, '*u8')
            self.read('Offset',      file, '*u8')
            self.read('Size',        file, '*u8')
            self.read('Link',        file, '*u4')
            self.read('Info',        file, '*u4')
            self.read('AddrAlign',   file, '*u8')
            self.read('EntSize',     file, '*u8')

        self._end_offset = file.tell()

        file.seek(self.Offset)
        self.read('_Section', file, Section, {
            'Size': self.Size,
            'Flags': self.Flags,
        })
        file.seek(self._end_offset)

    def update_name(self, data):
        self.Name = get_null_string(data, self.Name)


class ELF(Struct):
    def __init__(self, file, path):
        super().__init__(
            filter=['ProgramHeaders', 'SectionHeaders']
        )

        section = ['.text', '.data', '.bss', '.rodata', '.comment']

        self._file = file
        self._path = path

        self.read('FileHeader', file, FileHeader)

        if self.FileHeader.ProgramHeaderNum > 0:
            self.read('ProgramHeaders', file, [ProgramHeader for i in range(self.FileHeader.ProgramHeaderNum)], {
                '_Class': self.FileHeader._Class
            })

        if self.FileHeader.SectionHeaderNum > 0:
            file.seek(self.FileHeader.SectionHeaderOffset)
            self.read('SectionHeaders', file, [SectionHeader for i in range(self.FileHeader.SectionHeaderNum)], {
                '_Class': self.FileHeader._Class
            })

            strtab = self.SectionHeaders[self.FileHeader.StringTableIndex]._Section._data
            for sh in self.SectionHeaders:
                sh.update_name(strtab)

                if sh.Name in section:
                    setattr(self, sh.Name, sh._Section)
