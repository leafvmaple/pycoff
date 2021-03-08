from .utility import Struct

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
            self.read('Phoff', file, '*u4')
            self.read('Shoff', file, '*u4')
        else:
            self.read('Entry', file, '*u8')
            self.read('Phoff', file, '*u8')
            self.read('Shoff', file, '*u8')

        self.read('Flags',               file, '*u4')
        self.read('FileHeaderSize',      file, '*u2')
        self.read('ProgramHeaderSize',   file, '*u2')
        self.read('ProgramHeaderNum',    file, '*u2')
        self.read('SectionHeaderSize',   file, '*u2')
        self.read('SectionHeaderNum',    file, '*u2')
        self.read('SectionHeaderStrIdx', file, '*u2')


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


class ELF(Struct):
    def __init__(self, file, path):
        super().__init__()

        self._file = file
        self._path = path

        self.read('FileHeader',    file, FileHeader)
        self.read('ProgramHeader', file, [ProgramHeader for i in range(self.FileHeader.ProgramHeaderNum)], {
            '_Class': self.FileHeader._Class
        })

        print(file.read(16))
