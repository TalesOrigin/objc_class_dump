import os
import struct
from enum import Enum

from exception import UnknownMagic

class MACH_O_LOAD_COMMAND_TYPE(Enum):
    SEGMENT = 0x1           #File segment to be mapped.
    SYMTAB = 0x2            #Link-edit stab symbol table info (obsolete).
    SYMSEG = 0x3            #Link-edit gdb symbol table info.
    THREAD = 0x4            #Thread.
    UNIXTHREAD = 0x5        #UNIX thread (includes a stack).
    LOADFVMLIB = 0x6        #Load a fixed VM shared library.
    IDFVMLIB = 0x7          #Fixed VM shared library id.
    IDENT = 0x8             #Object identification information (obsolete).
    FVMFILE = 0x9           #Fixed VM file inclusion.
    PREPAGE = 0xa           #Prepage command (internal use).
    DYSYMTAB = 0xb          #Dynamic link-edit symbol table info.
    LOAD_DYLIB = 0xc        #Load a dynamically linked shared library.
    ID_DYLIB = 0xd          #Dynamically linked shared lib identification.
    LOAD_DYLINKER = 0xe     #Load a dynamic linker.
    ID_DYLINKER = 0xf       #Dynamic linker identification.
    PREBOUND_DYLIB = 0x10   #Modules prebound for a dynamically.
    ROUTINES = 0x11         #Image routines.
    SUB_FRAMEWORK = 0x12    #Sub framework.
    SUB_UMBRELLA = 0x13     #Sub umbrella.
    SUB_CLIENT = 0x14       #Sub client.
    SUB_LIBRARY = 0x15      #Sub library.
    TWOLEVEL_HINTS = 0x16   #Two-level namespace lookup hints.
    PREBIND_CKSUM = 0x17    #Prebind checksum.
    #Load a dynamically linked shared library that is allowed to be missing (weak).
    WEAK_DYLIB = 0x80000018
    SEGMENT_64 = 0x19       #64-bit segment of this file to be mapped.
    ROUTINES_64 = 0x1a      #Address of the dyld init routine in a dylib.
    UUID = 0x1b             #128-bit UUID of the executable.
    RPATH = 0x8000001c            #Run path addiions.
    CODE_SIGNATURE = 0x1d   #Local of code signature.
    SEGMENT_SPLIT_INFO = 0x1e   #Local of info to split seg.
    REEXPORT_DYLIB = 0x1f   #Load and re-export lib.
    LAZY_LOAD_DYLIB = 0x20  #Delay load of lib until use.
    ENCRYPTION_INFO = 0x21  #Encrypted segment info.
    DYLD_INFO = 0x80000022        #Compressed dyld information.
    DYLD_INFO_ONLY = 0x80000022   #Alias of DYLD_INFO: LC_DYLD_INFO_ONLY, only dyld may read it.
    LOAD_UPWARD_DYLIB = 0x23    #Load upward dylib.
    VERSION_MIN_MACOSX = 0x24   #Minimal MacOSX version.
    VERSION_MIN_IPHONEOS = 0x25 #Minimal IOS version.
    FUNCTION_STARTS = 0x26      #Compressed table of func start.
    DYLD_ENVIRONMENT = 0x27     #Env variable string for dyld.
    MAIN = 0x80000028                 #Entry point.
    DATA_IN_CODE = 0x29         #Table of non-instructions.
    SOURCE_VERSION = 0x2a       #Source version.
    DYLIB_CODE_SIGN_DRS = 0x2b  #DRs from dylibs.
    ENCRYPTION_INFO_64 = 0x2c   #Encrypted 64 bit seg info.
    LINKER_OPTIONS = 0x2d       #Linker options.
    LINKER_OPTIMIZATION_HINT = 0x2e #Optimization hints.
    VERSION_MIN_TVOS = 0x2f     #Minimal TvOS version.
    VERSION_MIN_WATCHOS = 0x30  #Minimal WatchOS version.
    NOTE = 0x31                 #Region of arbitrary data included in the binary.
    BUILD_VERSION = 0x32        #Platform, minimum OS version and build tool versions.
    DYLD_EXPORTS_TRIE = 0x80000033  #Used with linkedit dyld export trie (LC_REQ_DYLD).
    DYLD_CHAINED_FIXUPS = 0x80000034    #Used with linkedit dyld chained fixups (LC_REQ_DYLD).
    FILESET_ENTRY = 0x80000035  #Used with fileset_entry_command (LC_REQ_DYLD).
    SEGMENT_SPLIT_RWE_INFO = 0x36   #Location of rwe segment split info.
    ATOM_INFO = 0x41            #Linker atom information.

#LC_REQ_DYLD marks load commands the dynamic linker is required to understand.
MACH_O_LC_REQ_DYLD = 0x80000000

def load_command_type(cmd):
    '''
    Translate a raw load command value into a MACH_O_LOAD_COMMAND_TYPE member.

    Returns None instead of raising for values this tool does not know about,
    so that Mach-O files using newer load commands can still be parsed: unknown
    commands are simply skipped by using their cmdsize.
    '''
    try:
        return MACH_O_LOAD_COMMAND_TYPE(cmd)
    except ValueError:
        return None

def load_command_name(cmd):
    '''Best effort name for a load command, used for diagnostics.'''
    lcmd = load_command_type(cmd)
    if lcmd == None:
        return 'LC_UNKNOWN(0x{:X})'.format(cmd)
    return lcmd.name

class MACH_O_SECTION_TYPE(Enum):
    #/* Regular section.  */
    REGULAR = 0x0

    #/* Zero fill on demand section.  */
    ZEROFILL = 0x1

    #/* Section with only literal C strings.  */
    CSTRING_LITERALS = 0x2

    #/* Section with only 4 byte literals.  */
    FOUR_BYTE_LITERALS = 0x3

    #/* Section with only 8 byte literals.  */
    EIGHT_BYTE_LITERALS = 0x4

    #/* Section with only pointers to literals.  */
    LITERAL_POINTERS = 0x5

    '''
    For the two types of symbol pointers sections and the symbol stubs
    section they have indirect symbol table entries.  For each of the
    entries in the section the indirect symbol table entries, in
    corresponding order in the indirect symbol table, start at the index
    stored in the reserved1 field of the section structure.  Since the
    indirect symbol table entries correspond to the entries in the
    section the number of indirect symbol table entries is inferred from
    the size of the section divided by the size of the entries in the
    section.  For symbol pointers sections the size of the entries in
    the section is 4 bytes and for symbol stubs sections the byte size
    of the stubs is stored in the reserved2 field of the section
    structure.
    '''

    #/* Section with only non-lazy symbol pointers.  */
    NON_LAZY_SYMBOL_POINTERS = 0x6

    #/* Section with only lazy symbol pointers.  */
    LAZY_SYMBOL_POINTERS = 0x7

    #/* Section with only symbol stubs, byte size of stub in the reserved2 field.  */
    SYMBOL_STUBS = 0x8

    #/* Section with only function pointers for initialization.  */
    MOD_INIT_FUNC_POINTERS = 0x9

    #/* Section with only function pointers for termination.  */
    MOD_FINI_FUNC_POINTERS = 0xa

    #/* Section contains symbols that are coalesced by the linkers.  */
    COALESCED = 0xb

    #/* Zero fill on demand section (possibly larger than 4 GB).  */
    GB_ZEROFILL = 0xc

    #/* Section with only pairs of function pointers for interposing.  */
    INTERPOSING = 0xd

    #/* Section with only 16 byte literals.  */
    SIXTEEN_BYTE_LITERALS = 0xe

    #/* Section contains DTrace Object Format.  */
    DTRACE_DOF = 0xf

    #/* Section with only lazy symbol pointers to lazy loaded dylibs.  */
    LAZY_DYLIB_SYMBOL_POINTERS = 0x10

class DYLD_INFO_BIND_OPCODE(Enum):
    #Constants for dyld info bind.
    OPCODE_MASK = 0xf0
    IMMEDIATE_MASK = 0x0f
    
    #The bind opcodes
    DONE = 0x00
    SET_DYLIB_ORDINAL_IMM = 0x10
    SET_DYLIB_ORDINAL_ULEB = 0x20
    SET_DYLIB_SPECIAL_IMM = 0x30
    SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40
    SET_TYPE_IMM = 0x50
    SET_ADDEND_SLEB = 0x60
    SET_SEGMENT_AND_OFFSET_ULEB = 0x70
    ADD_ADDR_ULEB = 0x80
    DO_BIND = 0x90
    DO_BIND_ADD_ADDR_ULEB = 0xa0
    DO_BIND_ADD_ADDR_IMM_SCALED = 0xb0
    DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xc0

class DYLD_INFO_BIND_TYPE(Enum):
    #The bind types.
    POINTER = 1
    TEXT_ABSOLUTE32 = 2
    TEXT_PCREL32 = 3

'''
Since macOS 10.15 / iOS 13.4 the linker can emit chained fixups (LC_DYLD_CHAINED_FIXUPS)
instead of the classic LC_DYLD_INFO/LC_DYLD_INFO_ONLY opcode streams. Every pointer in a
fixup page then holds an encoded target which must be decoded to get the real vmaddr, and
the import table lives in the linkedit payload referenced by the load command.

struct dyld_chained_fixups_header
{
    uint32_t    fixups_version;     // 0
    uint32_t    starts_offset;      // offset of dyld_chained_starts_in_image in chain_data
    uint32_t    imports_offset;     // offset of imports table in chain_data
    uint32_t    symbols_offset;     // offset of symbol strings in chain_data
    uint32_t    imports_count;      // number of imported symbol names
    uint32_t    imports_format;     // DYLD_CHAINED_IMPORT*
    uint32_t    symbols_format;     // 0 => uncompressed, 1 => zlib compressed
};
'''
class DYLD_CHAINED_IMPORT_FORMAT(Enum):
    UNCOMPRESSED = 1          #struct dyld_chained_import: lib_ordinal:8, weak_import:1, name_offset:23
    COMPRESSED = 2            #struct dyld_chained_import_addend: ... name_offset:23, addend:sleb 4bytes
    COMPRESSED_64 = 3         #struct dyld_chained_import_addend64: ... name_offset:24, addend:sleb 8bytes

#Special (negative) library ordinals used by chained fixup bind entries.
DYLD_CHAINED_IMPORT_SELF = 0
DYLD_CHAINED_IMPORT_MAIN_EXECUTABLE = -1
DYLD_CHAINED_IMPORT_FLAT_LOOKUP = -2
DYLD_CHAINED_IMPORT_WEAK_LOOKUP = -3

class DYLD_CHAINED_PTR_FORMAT(Enum):
    #/* <mach-o/chained_fixups.h> */
    NONE = 0
    ARM64E_CACHEABLE = 1
    X86_64_CACHEABLE = 2
    ARM64 = 3
    ARM64E = 4
    ARM64E_USERLAND = 5
    ARM64E_FIRMWARE = 6
    ARM64E_USERLAND24 = 7
    X86_64_KERNEL_CACHEABLE = 8
    ARM64E_KERNEL = 9
    ARM64_32 = 10
    ARM64E_KERNEL64 = 11
    ARM64_32_KERNEL_CACHEABLE = 12

#Formats whose rebase target is an offset relative to the preferred load address of the
#segment instead of an absolute vmaddr. Only the kernel/firmware formats work that way,
#every user space format stores the full unslid vmaddr in the pointer.
DYLD_CHAINED_PTR_FORMAT_SEGMENT_RELATIVE = (
    DYLD_CHAINED_PTR_FORMAT.ARM64E_FIRMWARE,
    DYLD_CHAINED_PTR_FORMAT.ARM64E_KERNEL,
    DYLD_CHAINED_PTR_FORMAT.ARM64E_KERNEL64,
)

#Pointer formats this tool knows how to decode, mapped to the size of a chained pointer.
DYLD_CHAINED_PTR_FORMAT_SIZE = {
    DYLD_CHAINED_PTR_FORMAT.ARM64: 8,
    DYLD_CHAINED_PTR_FORMAT.ARM64E: 8,
    DYLD_CHAINED_PTR_FORMAT.ARM64E_USERLAND: 8,
    DYLD_CHAINED_PTR_FORMAT.ARM64E_USERLAND24: 8,
    DYLD_CHAINED_PTR_FORMAT.ARM64E_FIRMWARE: 8,
    DYLD_CHAINED_PTR_FORMAT.ARM64E_KERNEL: 8,
    DYLD_CHAINED_PTR_FORMAT.ARM64E_KERNEL64: 8,
    DYLD_CHAINED_PTR_FORMAT.ARM64E_CACHEABLE: 8,
    DYLD_CHAINED_PTR_FORMAT.X86_64_CACHEABLE: 8,
    DYLD_CHAINED_PTR_FORMAT.X86_64_KERNEL_CACHEABLE: 8,
    DYLD_CHAINED_PTR_FORMAT.ARM64_32: 4,
    DYLD_CHAINED_PTR_FORMAT.ARM64_32_KERNEL_CACHEABLE: 4,
}

class DYLD_CHAINED_FIXUPS:
    '''Content of the linkedit payload pointed at by LC_DYLD_CHAINED_FIXUPS.'''
    def __init__(self, dataoff, datasize):
        self.dataoff = dataoff
        self.datasize = datasize
        self.fixups_version = 0
        self.starts_offset = 0
        self.imports_offset = 0
        self.symbols_offset = 0
        self.imports_count = 0
        self.imports_format = None
        self.symbols_format = 0
        self.imports = []         #list of (lib_ordinal, weak_import, name_offset, addend)

class DYLD_CHAINED_STARTS_IN_SEGMENT:
    '''
    struct dyld_chained_starts_in_segment
    {
        uint32_t    size;               // size of this (amount to jump to next dyld_chained_starts_in_segment)
        uint16_t    page_size;          // 0x1000 or 0x4000
        uint16_t    pointer_format;     // DYLD_CHAINED_PTR*
        uint64_t    segment_offset;     // offset in memory to start of segment
        uint32_t    max_valid_pointer;  // for 32-bit OS, the largest rebase address that is valid
        uint32_t    page_count;         // number of pages in array
        uint16_t    page_start[];       // each is the offset in the page of the first element in the chain
    };
    '''
    HEADER_SIZE = 24
    SIZE = 44

    def __init__(self, size, page_size, pointer_format, segment_offset, max_valid_pointer, page_count, page_start_off):
        self.size = size
        self.page_size = page_size
        self.pointer_format = pointer_format
        self.segment_offset = segment_offset
        self.max_valid_pointer = max_valid_pointer
        self.page_count = page_count
        self.page_start_off = page_start_off
        self.page_start = []

    def ptr_size(self):
        return DYLD_CHAINED_PTR_FORMAT_SIZE.get(self.pointer_format)

    def is_decodable(self):
        return self.ptr_size() != None and self.page_count > 0

    def is_target_segment_relative(self):
        return self.pointer_format in DYLD_CHAINED_PTR_FORMAT_SEGMENT_RELATIVE

    #Resolve the target field of a rebase entry into a vmaddr
    def rebase_target(self, target):
        if self.is_target_segment_relative():
            return self.segment_offset + target
        return target

DYLD_CHAINED_STARTS_IN_PAGE_END = 0x8000
DYLD_CHAINED_STARTS_IN_PAGE_NO_REBIND = 0xFFFF

class ChainedFixups:
    '''Parsed LC_DYLD_CHAINED_FIXUPS: the header plus the per segment chain starts.'''
    def __init__(self, header, starts_in_segments):
        self.header = header
        self.starts_in_segments = starts_in_segments

class MachHeader:
    '''
    #define MH_MAGIC 0xfeedface
    #define MH_CIGAM 0xcefaedfe
    struct mach_header
    {
        unsigned long magic;      /* Magic number.  */
        unsigned long cputype;    /* CPU that this object is for.  */
        unsigned long cpusubtype; /* CPU subtype.  */
        unsigned long filetype;   /* Type of file.  */
        unsigned long ncmds;      /* Number of load commands.  */
        unsigned long sizeofcmds; /* Total size of load commands.  */
        unsigned long flags;      /* Flags for special featues.  */
    };
    
    #define MH_MAGIC_64 0xfeedfacf
    #define MH_CIGAM_64 0xcffaedfe
    struct mach_header_64
    {
        unsigned long magic;      /* Magic number.  */
        unsigned long cputype;    /* CPU that this object is for.  */
        unsigned long cpusubtype; /* CPU subtype.  */
        unsigned long filetype;   /* Type of file.  */
        unsigned long ncmds;      /* Number of load commands.  */
        unsigned long sizeofcmds; /* Total size of load commands.  */
        unsigned long flags;      /* Flags for special featues.  */
        unsigned long reserved;   /* Reserved.  Duh.  */
    };
    '''
    def __init__(self, mach_o_file, file_offset):
        __MH_MAGIC = b'\xfe\xed\xfa\xce'
        __MH_CIGAM = b'\xce\xfa\xed\xfe'
        __MH_MAGIC_64 = b'\xfe\xed\xfa\xcf'
        __MH_CIGAM_64 = b'\xcf\xfa\xed\xfe'
        
        mach_o_file.seek(file_offset)

        magic = mach_o_file.read(4)
        
        if magic == __MH_MAGIC or magic == __MH_CIGAM:
            self.__big_endian = (magic == __MH_MAGIC)
            self.__64bit_cpu = False
            self.__hdr_len = 28
        elif magic == __MH_MAGIC_64 or magic == __MH_CIGAM_64:
            self.__big_endian = (magic == __MH_MAGIC_64)
            self.__64bit_cpu = True
            self.__hdr_len = 32
        else:
            raise UnknownMagic(magic)
            
        if self.__big_endian == True:
            endian_str = '>'
        else:
            endian_str = '<'

        #skip cuptype, cpusubtype and filetype
        mach_o_file.seek(12, os.SEEK_CUR)
        self.__number_cmds, self.__sizeof_cmds = struct.unpack(endian_str + 'LL', mach_o_file.read(8))

    def is_big_endian(self):
        return self.__big_endian
    def is_64bit_cpu(self):
        return self.__64bit_cpu
    def get_hdr_len(self):
        return self.__hdr_len
    def get_number_cmds(self):
        return self.__number_cmds
    def get_sizeof_cmds(self):
        return self.__sizeof_cmds

class Segment:
    def __init__(self, name, vmaddr, vmsize, offset, filesize, maxprot, initprot, nsects, flags):
        self.name = name
        self.vmaddr = vmaddr
        self.vmsize = vmsize
        self.offset = offset
        self.filesize = filesize
        self.maxprot = maxprot
        self.initprot = initprot
        self.nsects = nsects
        self.flags = flags
        self.sections = []

    def append_section(self, section):
            self.sections.append(section)
        
class Section:
    def __init__(self, name, vmaddr, vmsize, offset, alignment, reloff, nreloc, flags, reserved1, reserved2, reserved3=None):
        self.name = name
        self.vmaddr = vmaddr
        self.vmsize = vmsize
        self.offset = offset
        self.alignment = alignment
        self.reloff = reloff
        self.nreloc = nreloc
        self.flags = flags
        self.reserved1 = reserved1
        self.reserved2 = reserved2
        self.reserved3 = reserved3
        self.data = None
        
    def buf_data(self, data):
        self.data = data

class DYLib:
    def __init__(self, timestamp, current_ver, compat_ver, name):
        self.timestamp = timestamp
        self.current_ver = current_ver
        self.compat_ver = compat_ver
        self.name = name
        self.symbols = []
        
    def append_symbol(self, symbol):
        if symbol not in self.symbols:
            self.symbols.append(symbol)
    
class DYLDInfo:
    def __init__(self, rebase_off, rebase_size, bind_off, bind_size, weak_bind_off, weak_bind_size, lazy_bind_off, lazy_bind_size, export_off, export_size):
        self.rebase_off = rebase_off
        self.rebase_size = rebase_size
        self.bind_off = bind_off
        self.bind_size = bind_size
        self.weak_bind_off = weak_bind_off
        self.weak_bind_size = weak_bind_size
        self.lazy_bind_off = lazy_bind_off
        self.lazy_bind_size = lazy_bind_size
        self.export_off = export_off
        self.export_size = export_size

class VirtualMap:
    def __init__(self, addr, symbol):
        self.addr = addr
        self.symbol = symbol

