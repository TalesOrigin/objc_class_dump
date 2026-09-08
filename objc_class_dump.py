import sys
import os
import struct
import leb128
from exception import UnknownMagic, UnsupportBindOpcode
from macho import MACH_O_CPU_TYPE
from fat_header import FatHeader
from mach_header import *
from objc import *

#Section and string data is read as raw bytes from the Mach-O file,
#decode it to str for display and comparison purposes.
#backslashreplace keeps the decoding lossless for any malformed bytes.
def bytes_to_str(data):
    return data.decode('utf-8', 'backslashreplace')

class MachOAnalyzer:
    def __init__(self, file, cpu_type=MACH_O_CPU_TYPE.ARM64):
        self.__fd = file

        try:
            self.__fat_header = FatHeader(self.__fd)

            print('FAT Mach-O detected')
            fat_arch = self.__fat_header.get_arch(cpu_type)
            if fat_arch == None:
                print('No arch for', cpu_type, ' in FAT Header')
                fat_arch = self.__fat_header.get_arch()
                print('Using the first avaiable arch:', fat_arch.get_cpu_type())
            self.__mh_offset = fat_arch.get_file_offset()
        except UnknownMagic:
            print('Mach-O detected')
            self.__mh_offset = 0

        self.__mach_header = MachHeader(self.__fd, self.__mh_offset)

        if True == self.__mach_header.is_big_endian():
            self.__endian_str = '>'
        else:
            self.__endian_str = '<'
            
        if True == self.__mach_header.is_64bit_cpu():
            self.__is_64bit_cpu = True
        else:
            self.__is_64bit_cpu = False

        self.__segments = self.__build_segments()
        if len(self.__segments) == 0:
            print('Warning: no segment found, the Mach-O file cannot be analyzed')

        self.__dylibs = self.__build_load_dylib()

        self.__chained_fixups = None
        self.__chained_fixups_data = b''

        dyld_info = self.get_dyld_info()

        #Modern binaries (iOS 13.4+/macOS 10.15+ toolchains) may carry their binding
        #information in LC_DYLD_CHAINED_FIXUPS instead of LC_DYLD_INFO(_ONLY).
        self.__chained_fixups = self.__parse_chained_fixups()

        #pass1: build the import table
        if dyld_info.bind_size != 0:
            #print 'bind pass1'
            self.__build_bind_info(dyld_info.bind_off, dyld_info.bind_size, self.__bind_pass1)

        if dyld_info.weak_bind_size != 0:
            #print 'weak bind pass1'
            self.__build_bind_info(dyld_info.weak_bind_off, dyld_info.weak_bind_size, self.__bind_pass1)

        if dyld_info.lazy_bind_size != 0:
            #print 'lazy bind pass1'
            self.__build_bind_info(dyld_info.lazy_bind_off, dyld_info.lazy_bind_size, self.__bind_pass1)

        if self.__chained_fixups != None:
            #print 'chained fixups pass1'
            self.__build_chained_fixups_info(self.__chained_fixups_bind_pass1)

        #build virtual section from the import table
        #TODO revise the data structure for addend
        self.__virtual_section = self.__build_virtual_section()

        #pass2: bind address to virtual section
        if dyld_info.bind_size != 0:
            #print 'bind pass2'
            self.__build_bind_info(dyld_info.bind_off, dyld_info.bind_size, self.__bind_pass2)

        if dyld_info.weak_bind_size != 0:
            #print 'weak bind pass2'
            self.__build_bind_info(dyld_info.weak_bind_off, dyld_info.weak_bind_size, self.__bind_pass2)

        if dyld_info.lazy_bind_size != 0:
            #print 'lazy bind pass2'
            self.__build_bind_info(dyld_info.lazy_bind_off, dyld_info.lazy_bind_size, self.__bind_pass2)

        if self.__chained_fixups != None:
            #print 'chained fixups pass2'
            self.__build_chained_fixups_info(self.__chained_fixups_bind_pass2)

        self.__objc2_cls_stack = []
        self.__resloved_objc2_cls_list = []

        self.__objc_classlist = self.__build_objc2_clslist()
        self.__objc_nlclslist = self.__build_objc2_nlclslist()

    '''
    struct segment_command
    {
        unsigned long type;
        unsigned long len;
        char segment_name[16];
        unsigned long vmaddr;
        unsigned long vmsize;
        unsigned long fileoff;
        unsigned long filesize;
        unsigned long maxprot;
        unsigned long initprot;
        unsigned long nsects;
        unsigned long flags;
    }
    
    struct segment_command_64
    {
        unsigned long type;
        unsigned long len;
        char segment_name[16];
        unsigned long long vmaddr;
        unsigned long long vmsize;
        unsigned long long fileoff;
        unsigned long long filesize;
        unsigned long maxprot;
        unsigned long initprot;
        unsigned long nsects;
        unsigned long flags;
    }

    struct section
    {
        char section_name[16];
        char segment_name[16];
        unsigned long addr;
        unsigned long size;
        unsigned long offset;
        unsigned long alignment;
        unsigned long reloff;
        unsigned long nreloc
        unsigned long flags;
        unsigned long reserved1;
        unsigned long reserved2;
    }
    
    struct section_64
    {
        char section_name[16];
        char segment_name[16];
        unsigned long long addr;
        unsigned long long size;
        unsigned long offset;
        unsigned long alignment;
        unsigned long reloff;
        unsigned long nreloc
        unsigned long flags;
        unsigned long reserved1;
        unsigned long reserved2;
        unsigned long reserved3;
    }
    '''
    #Build Segment and section list in memory
    def __build_segments(self):
        n_lcmds = self.__mach_header.get_number_cmds()
        self.__fd.seek(self.__mh_offset + self.__mach_header.get_hdr_len())

        segments = []
        cmds_end = self.__mh_offset + self.__mach_header.get_hdr_len() + self.__mach_header.get_sizeof_cmds()
        for i in range(n_lcmds):
            if self.__fd.tell() + 8 > cmds_end:
                print('Warning: load command {:d} is outside of the load command region, stop walking'.format(i))
                break
            type, len = struct.unpack(self.__endian_str + 'LL', self.__fd.read(8))
            cmd_type = load_command_type(type)
            if len < 8:
                print('Warning: invalid load command size ({:d}) at load command {:d}, stop walking'.format(len, i))
                break
            if self.__is_64bit_cpu == True and cmd_type == MACH_O_LOAD_COMMAND_TYPE.SEGMENT_64:
                name, vmaddr, vmsize, offset, filesize, maxprot, initprot, nsects, flags = \
                    struct.unpack(self.__endian_str + '16sQQQQLLLL', self.__fd.read(64))
                name = bytes_to_str(name.strip(b'\x00'))
                segment = Segment(name, vmaddr, vmsize, offset, filesize, maxprot, initprot, nsects, flags)
                segments.append(segment)
                
                for j in range(nsects):
                    sec_name, name, vmaddr, vmsize, offset, alignment, reloff, nreloc, flags, reserved1, reserved2, reserved3 = \
                        struct.unpack(self.__endian_str + '16s16sQQLLLLLLLL', self.__fd.read(80))
                    sec_name = bytes_to_str(sec_name.strip(b'\x00'))
                    section = Section(sec_name, vmaddr, vmsize, offset, alignment, reloff, nreloc, flags, reserved1, reserved2, reserved3)
                    segment.append_section(section)
                    
            elif self.__is_64bit_cpu == False and cmd_type == MACH_O_LOAD_COMMAND_TYPE.SEGMENT:
                name, vmaddr, vmsize, offset, filesize, maxprot, initprot, nsects, flags = \
                    struct.unpack(self.__endian_str + '16sLLLLLLLL', self.__fd.read(48))
                name = bytes_to_str(name.strip(b'\x00'))
                segment = Segment(name, vmaddr, vmsize, offset, filesize, maxprot, initprot, nsects, flags)
                segments.append(segment)

                for j in range(nsects):
                    sec_name, name, vmaddr, vmsize, offset, alignment, reloff, nreloc, flags, reserved1, reserved2 = \
                        struct.unpack(self.__endian_str + '16s16sLLLLLLLLL', self.__fd.read(68))
                    sec_name = bytes_to_str(sec_name.strip(b'\x00'))
                    section = Section(sec_name, vmaddr, vmsize, offset, alignment, reloff, nreloc, flags, reserved1, reserved2)
                    segment.append_section(section)
            else:
                self.__fd.seek(len - 8, os.SEEK_CUR)

        for segment in segments:
            for section in segment.sections:
                self.__fd.seek(self.__mh_offset + section.offset)
                section.buf_data(self.__fd.read(section.vmsize))
                
        return segments
                
    '''
    struct load_dylib
    {
        unsigned long type;
        unsigned long len;
        unsigned long name_off;
        unsigned long timestamp;
        unsigned long current_ver;
        unsigned long compat_ver;
        char lib_name[];
    }
    '''
    #Build dylib name list from LC_LOAD_DYLIB
    def __build_load_dylib(self):
        #skip mach header to load commands
        offset = self.__mach_header.get_hdr_len()
        n_cmds = self.__mach_header.get_number_cmds()
        self.__fd.seek(self.__mh_offset + offset)

        dylibs = []
        dylib_cmd_count = 0
        cmds_end = self.__mh_offset + offset + self.__mach_header.get_sizeof_cmds()
        for i in range(n_cmds):
            if self.__mh_offset + offset + dylib_cmd_count + 8 > cmds_end:
                print('Warning: load command {:d} is outside of the load command region, stop walking'.format(i))
                break
            type, lc_len = struct.unpack(self.__endian_str + 'LL', self.__fd.read(8))
            if lc_len < 8:
                print('Warning: invalid load command size ({:d}) at load command {:d}, stop walking'.format(lc_len, i))
                break
            cmd_type = load_command_type(type)
            if cmd_type == MACH_O_LOAD_COMMAND_TYPE.LOAD_DYLIB or \
                cmd_type == MACH_O_LOAD_COMMAND_TYPE.WEAK_DYLIB or \
                cmd_type == MACH_O_LOAD_COMMAND_TYPE.REEXPORT_DYLIB or \
                cmd_type == MACH_O_LOAD_COMMAND_TYPE.LAZY_LOAD_DYLIB or \
                cmd_type == MACH_O_LOAD_COMMAND_TYPE.LOAD_UPWARD_DYLIB or \
                cmd_type == MACH_O_LOAD_COMMAND_TYPE.ID_DYLIB:
                off, ts, cur_ver, compat_ver = struct.unpack(self.__endian_str + 'LLLL', self.__fd.read(16))

                #the install name does not have to directly follow the dylib_command header,
                #it is located at name_off bytes from the beginning of the load command
                self.__fd.seek(self.__mh_offset + offset + dylib_cmd_count + off)
                c_str = b''
                while True:
                    c = self.__fd.read(1)
                    if not c or c == b'\x00':
                        break
                    c_str = c_str + c

                dylib = DYLib(ts, cur_ver, compat_ver, bytes_to_str(c_str))
                dylibs.append(dylib)
                dylib_cmd_count += lc_len
            else:
                dylib_cmd_count += lc_len

            self.__fd.seek(self.__mh_offset + offset + dylib_cmd_count)
        return dylibs

    def get_dylib(self, lib_idx):
        if lib_idx < 0 or lib_idx >= len(self.__dylibs):
            return None
        return self.__dylibs[lib_idx]

    #Library ordinal of a dyld_info bind opcode, 1 based index into the dylib list
    def get_dylib_by_ordinal(self, lib_ordinal):
        return self.get_dylib(lib_ordinal - 1)

    #Library ordinal of a chained fixup bind entry. Chained fixups use special
    #negative/zero ordinals which do not refer to an entry of the dylib list.
    def get_chained_dylib_by_ordinal(self, lib_ordinal):
        if lib_ordinal > 0:
            return self.get_dylib(lib_ordinal - 1)
        return None

    '''
    struct dyld_info
    {
        unsigned long type;
        unsigned long len;
        unsigned long rebase_off;
        unsigned long rebase_size;
        unsigned long bind_off;
        unsigned long bind_size;
        unsigned long week_bind_off;
        unsigned long week_bind_size;
        unsigned long lazy_bind_off;
        unsigned long lazy_bind_size;
        unsigned long export_off;
        unsigned long export_size;
    }
    '''
    #Search for segment LOAD_COMMAND_DYLD_INFO and return its fields
    def get_dyld_info(self):
        offset = self.__mach_header.get_hdr_len()
        n_cmds = self.__mach_header.get_number_cmds()
        self.__fd.seek(self.__mh_offset + offset)

        rebase_off = 0
        rebase_size = 0
        bind_off = 0
        bind_size = 0
        weak_bind_off = 0
        weak_bind_size = 0
        lazy_bind_off = 0
        lazy_bind_size = 0
        export_off = 0
        export_size = 0
        cmds_end = self.__mh_offset + offset + self.__mach_header.get_sizeof_cmds()
        for i in range(n_cmds):
            if self.__fd.tell() + 8 > cmds_end:
                break
            type, len = struct.unpack(self.__endian_str + 'LL', self.__fd.read(8))
            if len < 8:
                break
            cmd_type = load_command_type(type)

            #LC_DYLD_INFO (0x22) and LC_DYLD_INFO_ONLY (0x80000022) share the same struct
            #and the same enum member, DYLD_INFO_ONLY being an alias of DYLD_INFO
            if cmd_type == MACH_O_LOAD_COMMAND_TYPE.DYLD_INFO:
                rebase_off, rebase_size, bind_off, bind_size, weak_bind_off, weak_bind_size, lazy_bind_off, lazy_bind_size, export_off, export_size \
                    = struct.unpack(self.__endian_str + 'LLLLLLLLLL', self.__fd.read(40))
                break
            else:
                self.__fd.seek(len - 8, os.SEEK_CUR)
        
        dyld_info = DYLDInfo(rebase_off, rebase_size, bind_off, bind_size, weak_bind_off, weak_bind_size, lazy_bind_off, lazy_bind_size, export_off, export_size)
        return dyld_info

    '''
    struct linkedit_data_command
    {
        unsigned long cmd;        //LC_DYLD_CHAINED_FIXUPS or LC_DYLD_EXPORTS_TRIE
        unsigned long cmdsize;    // sizeof(struct linkedit_data_command)
        unsigned long dataoff;    // file offset of data in __LINKEDIT segment
        unsigned long datasize;   // file size of data in __LINKEDIT segment
    }
    '''
    #Search for LC_DYLD_CHAINED_FIXUPS and return the location of its payload
    def get_chained_fixups_cmd(self):
        offset = self.__mach_header.get_hdr_len()
        n_cmds = self.__mach_header.get_number_cmds()
        self.__fd.seek(self.__mh_offset + offset)

        cmds_end = self.__mh_offset + offset + self.__mach_header.get_sizeof_cmds()
        for i in range(n_cmds):
            if self.__fd.tell() + 8 > cmds_end:
                break
            type, len = struct.unpack(self.__endian_str + 'LL', self.__fd.read(8))
            if len < 8:
                break
            cmd_type = load_command_type(type)

            if cmd_type == MACH_O_LOAD_COMMAND_TYPE.DYLD_CHAINED_FIXUPS:
                dataoff, datasize = struct.unpack(self.__endian_str + 'LL', self.__fd.read(8))
                return DYLD_CHAINED_FIXUPS(dataoff, datasize)

            self.__fd.seek(len - 8, os.SEEK_CUR)
        return None

    '''
    struct dyld_chained_fixups_header
    {
        uint32_t    fixups_version;     // 0
        uint32_t    starts_offset;      // offset of dyld_chained_starts_in_image in chain_data
        uint32_t    imports_offset;     // offset of imports table in chain_data
        uint32_t    symbols_offset;     // offset of symbol strings in chain_data
        uint32_t    imports_count;      // number of imported symbol names
        uint32_t    imports_format;     // DYLD_CHAINED_IMPORT*
        uint32_t    symbols_format;     // 0 => uncompressed, 1 => zlib compressed
    }
    '''
    #Parse the LC_DYLD_CHAINED_FIXUPS payload: the header, the import table and the
    #per segment chain starts. Returns None if the binary does not use chained fixups.
    def __parse_chained_fixups(self):
        cmd = self.get_chained_fixups_cmd()
        if cmd == None:
            return None

        self.__fd.seek(self.__mh_offset + cmd.dataoff)
        chain_data = self.__fd.read(cmd.datasize)
        if len(chain_data) < 32:
            print('Warning: truncated LC_DYLD_CHAINED_FIXUPS payload, chained fixups ignored')
            return None

        fixups_version, starts_offset, imports_offset, symbols_offset, imports_count, imports_format, symbols_format = \
            struct.unpack('<LLLLLLL', chain_data[0:28])

        cmd.fixups_version = fixups_version
        cmd.starts_offset = starts_offset
        cmd.imports_offset = imports_offset
        cmd.symbols_offset = symbols_offset
        cmd.imports_count = imports_count
        cmd.symbols_format = symbols_format

        if symbols_format != 0:
            #zlib compressed symbol strings are not produced by the default toolchain
            print('Warning: compressed chained fixups symbol strings (format {:d}) are not supported'.format(symbols_format))

        try:
            cmd.imports_format = DYLD_CHAINED_IMPORT_FORMAT(imports_format)
        except ValueError:
            print('Warning: unknown chained fixups imports format 0x{:X}, import table ignored'.format(imports_format))
            cmd.imports_format = None

        #The chained fixups structures are defined little endian only
        self.__chained_fixups_data = chain_data
        cmd.imports = self.__parse_chained_fixups_imports(cmd, chain_data)
        starts_in_segments = self.__parse_chained_starts_in_image(chain_data, starts_offset)

        return ChainedFixups(cmd, starts_in_segments)

    #Decode the import table of a chained fixups payload
    def __parse_chained_fixups_imports(self, cmd, chain_data):
        imports = []
        if cmd.imports_format == None:
            return imports

        entry_fmt, entry_size = {
            DYLD_CHAINED_IMPORT_FORMAT.UNCOMPRESSED: ('<I', 4),
            DYLD_CHAINED_IMPORT_FORMAT.COMPRESSED: ('<I', 4),
            DYLD_CHAINED_IMPORT_FORMAT.COMPRESSED_64: ('<Q', 8),
        }[cmd.imports_format]

        name_offset_bits = 24 if cmd.imports_format == DYLD_CHAINED_IMPORT_FORMAT.COMPRESSED_64 else 23
        name_offset_mask = (1 << name_offset_bits) - 1

        for i in range(cmd.imports_count):
            pos = cmd.imports_offset + i * entry_size
            if pos + entry_size > len(chain_data):
                print('Warning: chained fixups import table is truncated at entry {:d}'.format(i))
                break
            raw, = struct.unpack(entry_fmt, chain_data[pos : pos + entry_size])

            lib_ordinal = raw & 0xFF
            if lib_ordinal > 0x7F:
                lib_ordinal = lib_ordinal - 0x100       #int8_t, negative means a special ordinal
            weak_import = (raw >> 8) & 0x1
            name_offset = (raw >> 9) & name_offset_mask

            addend = 0
            if cmd.imports_format == DYLD_CHAINED_IMPORT_FORMAT.COMPRESSED:
                addend, _ = leb128.decode_sleb128(chain_data[pos + 4 : len(chain_data)], len(chain_data) - (pos + 4))
            elif cmd.imports_format == DYLD_CHAINED_IMPORT_FORMAT.COMPRESSED_64:
                addend, _ = leb128.decode_sleb128(chain_data[pos + 8 : len(chain_data)], len(chain_data) - (pos + 8))

            imports.append((lib_ordinal, weak_import, name_offset, addend))
        return imports

    #Read a NUL terminated string out of the chained fixups symbol string pool
    def __get_chained_fixups_symbol(self, cmd, chain_data, name_offset):
        pos = cmd.symbols_offset + name_offset
        end = chain_data.find(b'\x00', pos)
        if end < 0:
            end = len(chain_data)
        return bytes_to_str(chain_data[pos:end])

    '''
    struct dyld_chained_starts_in_image
    {
        uint32_t    seg_count;
        uint32_t    seg_info_offset[seg_count];  // each entry is offset into this or zero
    };

    NOTE: despite the wording in the header, dyld treats seg_info_offset as an offset
    from the beginning of the LC_DYLD_CHAINED_FIXUPS payload, not from this structure:
        infoStart = (dyld_chained_starts_in_segment*)((uint8_t*)fixupsHeader + segInfoOffset)
    '''
    #Collect the chain starts of every segment
    def __parse_chained_starts_in_image(self, chain_data, starts_offset):
        starts_in_segments = []
        if starts_offset + 4 > len(chain_data):
            print('Warning: missing dyld_chained_starts_in_image in chained fixups payload')
            return starts_in_segments

        seg_count, = struct.unpack('<L', chain_data[starts_offset : starts_offset + 4])
        pos = starts_offset + 4
        if pos + seg_count * 4 > len(chain_data):
            print('Warning: truncated dyld_chained_starts_in_image, {:d} segments expected'.format(seg_count))
            seg_count = (len(chain_data) - pos) // 4

        for i in range(seg_count):
            seg_info_offset, = struct.unpack('<L', chain_data[pos : pos + 4])
            pos = pos + 4
            if seg_info_offset == 0:
                starts_in_segments.append(None)       #segment without any fixup
                continue
            starts_in_segments.append(self.__parse_chained_starts_in_segment(chain_data, seg_info_offset))
        return starts_in_segments

    def __parse_chained_starts_in_segment(self, chain_data, seg_info_pos):
        if seg_info_pos + DYLD_CHAINED_STARTS_IN_SEGMENT.SIZE > len(chain_data):
            print('Warning: truncated dyld_chained_starts_in_segment')
            return None

        size, page_size, pointer_format, segment_offset, max_valid_pointer, page_count = \
            struct.unpack('<LHHQLL', chain_data[seg_info_pos : seg_info_pos + DYLD_CHAINED_STARTS_IN_SEGMENT.HEADER_SIZE])

        try:
            ptr_format = DYLD_CHAINED_PTR_FORMAT(pointer_format)
        except ValueError:
            print('Warning: unknown chained pointer format {:d}'.format(pointer_format))
            ptr_format = DYLD_CHAINED_PTR_FORMAT.NONE

        page_start_off = seg_info_pos + DYLD_CHAINED_STARTS_IN_SEGMENT.HEADER_SIZE
        starts = DYLD_CHAINED_STARTS_IN_SEGMENT(size, page_size, ptr_format, segment_offset, max_valid_pointer, page_count, page_start_off)

        for i in range(page_count):
            if page_start_off + (i + 1) * 2 > len(chain_data):
                print('Warning: truncated page start array, {:d} of {:d} pages read'.format(i, page_count))
                break
            page_start, = struct.unpack('<H', chain_data[page_start_off + i * 2 : page_start_off + (i + 1) * 2])
            starts.page_start.append(page_start)

        if starts.page_size == 0:
            starts.page_size = 0x1000
        if starts.page_count > 0 and starts.ptr_size() == None:
            print('Warning: chained pointer format {:s} is not supported, fixups of segment at 0x{:X} ignored'.format(
                starts.pointer_format.name, segment_offset))
        return starts

    '''
    struct dyld_chained_ptr64_rebase { uint64_t target:36, high8:8, reserved:7, next:12, bind:1; };
    struct dyld_chained_ptr64_bind   { uint64_t ordinal:24, addend:8, reserved:19, next:12, bind:1; };
    struct dyld_chained_ptr_arm64e_rebase { uint64_t target:43, high8:8, reserved:2, next:11, bind:1; };
    struct dyld_chained_ptr_arm64e_bind   { uint64_t ordinal:16, addend:8, reserved:7, cacheLevel:2, diversity:12,
                                             addrDiv:1, key:2, next:11, bind:1; };
    struct dyld_chained_ptr_arm64e_bind24 { uint64_t ordinal:24, addend:8, reserved:19, cacheLevel:2, next:11, bind:1; };
    struct dyld_chained_ptr64_offset_rebase { uint64_t target:43, high8:8, reserved:7, next:4, bind:1, fixup:1; };
    struct dyld_chained_ptr64_kernel_cache_rebase { uint64_t target:30, cacheLevel:2, diversity:11, addrDiv:1,
                                                    key:2, next:12, isBind:1, fixup:1; };
    struct dyld_chained_ptr32_rebase { uint32_t target:26, next:5, bind:1; };
    struct dyld_chained_ptr32_bind   { uint32_t ordinal:20, next:5, bind:1; };
    struct dyld_chained_ptr32_cache_rebase { uint32_t target:30, next:1, bind:1; };
    struct dyld_chained_ptr32_firmware_rebase { uint32_t target:26, next:6; };
    '''
    #Decode one chained pointer. Returns a dict with the bind flag, the next chain offset
    #and either the imported symbol ordinal/addend (bind) or the raw target (rebase).
    def __decode_chained_pointer(self, fmt, raw, ptr_size):
        entry = {'bind': False, 'next': 0, 'ordinal': 0, 'addend': 0, 'target': 0}

        if fmt == DYLD_CHAINED_PTR_FORMAT.ARM64 or fmt == DYLD_CHAINED_PTR_FORMAT.ARM64_32:
            entry['next'] = (raw >> 51) & 0xFFF
            if (raw >> 63) & 1:
                entry['bind'] = True
                entry['ordinal'] = raw & 0xFFFFFF
                entry['addend'] = (raw >> 24) & 0xFF
            else:
                entry['target'] = raw & 0xFFFFFFFFF
                entry['target'] |= ((raw >> 43) & 0xFF) << 36

        elif fmt == DYLD_CHAINED_PTR_FORMAT.ARM64E or \
            fmt == DYLD_CHAINED_PTR_FORMAT.ARM64E_USERLAND or \
            fmt == DYLD_CHAINED_PTR_FORMAT.ARM64E_CACHEABLE or \
            fmt == DYLD_CHAINED_PTR_FORMAT.ARM64E_USERLAND24:
            entry['next'] = (raw >> 51) & 0x7FF
            if (raw >> 63) & 1:
                entry['bind'] = True
                if fmt == DYLD_CHAINED_PTR_FORMAT.ARM64E_USERLAND24:
                    entry['ordinal'] = raw & 0xFFFFFF
                else:
                    entry['ordinal'] = raw & 0xFFFF
                entry['addend'] = (raw >> 24) & 0xFF
            else:
                entry['target'] = raw & 0x7FFFFFFFFFF
                entry['target'] |= ((raw >> 43) & 0xFF) << 36

        elif fmt == DYLD_CHAINED_PTR_FORMAT.ARM64E_FIRMWARE or \
            fmt == DYLD_CHAINED_PTR_FORMAT.ARM64E_KERNEL or \
            fmt == DYLD_CHAINED_PTR_FORMAT.ARM64E_KERNEL64:
            #fixup bit is bit 0, the chain ends when the target is zero
            entry['next'] = 0
            if (raw >> 62) & 1:
                entry['next'] = (raw >> 51) & 0xFFF
            entry['target'] = raw & 0x3FFFFFFF
            if fmt == DYLD_CHAINED_PTR_FORMAT.ARM64E_KERNEL64:
                entry['target'] = raw & 0x3FFFFFFFFF
                entry['target'] |= ((raw >> 43) & 0xFF) << 36

        elif fmt == DYLD_CHAINED_PTR_FORMAT.X86_64_CACHEABLE or \
            fmt == DYLD_CHAINED_PTR_FORMAT.X86_64_KERNEL_CACHEABLE:
            entry['next'] = (raw >> 51) & 0xFFF
            if (raw >> 63) & 1:
                entry['bind'] = True
                entry['ordinal'] = raw & 0xFFFFFF
                entry['addend'] = (raw >> 24) & 0xFF
            else:
                entry['target'] = raw & 0xFFFFFFFFF
                entry['target'] |= ((raw >> 43) & 0xFF) << 36

        else:
            #32-bit formats
            entry['next'] = (raw >> 26) & 0x1F
            if fmt == DYLD_CHAINED_PTR_FORMAT.ARM64_32_KERNEL_CACHEABLE:
                entry['next'] = (raw >> 30) & 0x1
                entry['target'] = raw & 0x3FFFFFFF
            elif (raw >> 31) & 1:
                entry['bind'] = True
                entry['ordinal'] = raw & 0xFFFFF
            else:
                entry['target'] = raw & 0x3FFFFFF

        return entry

    #Walk every fixup page of every segment and call fixup_function once per chained pointer.
    #fixup_function(seg_idx, seg_off, ptr_vmaddr, target_vmaddr, dylib, symbol, addend)
    #ptr_vmaddr is the address the pointer itself lives at, target_vmaddr the value it has to
    #be fixed up to. For a bind entry symbol/dylib/addend are set and target_vmaddr is only
    #known once the virtual section has been built, so it is 0 during the first pass.
    def __build_chained_fixups_info(self, fixup_function):
        cmd = self.__chained_fixups.header
        chain_data = self.__chained_fixups_data

        for seg_idx in range(len(self.__chained_fixups.starts_in_segments)):
            if seg_idx >= len(self.__segments):
                break
            starts = self.__chained_fixups.starts_in_segments[seg_idx]
            if starts == None or not starts.is_decodable():
                continue

            segment = self.__segments[seg_idx]
            ptr_size = starts.ptr_size()
            ptr_fmt = '<Q' if ptr_size == 8 else '<L'

            for page_idx in range(starts.page_count):
                if page_idx >= len(starts.page_start):
                    break
                page_start = starts.page_start[page_idx]
                if page_start == DYLD_CHAINED_STARTS_IN_PAGE_END or page_start == DYLD_CHAINED_STARTS_IN_PAGE_NO_REBIND:
                    continue

                page_file_off = self.__mh_offset + segment.offset + page_idx * starts.page_size * 4
                page_seg_off = page_idx * starts.page_size * 4

                next_off = page_start
                while True:
                    seg_off = page_seg_off + next_off
                    self.__fd.seek(page_file_off + next_off)
                    raw_bytes = self.__fd.read(ptr_size)
                    if len(raw_bytes) != ptr_size:
                        print('Warning: chained fixups walk ran past the end of the file')
                        break
                    raw, = struct.unpack(ptr_fmt, raw_bytes)

                    entry = self.__decode_chained_pointer(starts.pointer_format, raw, ptr_size)

                    if entry['bind'] == True:
                        lib_ordinal = entry['ordinal']
                        addend = entry['addend']
                        symbol = None
                        dylib = None
                        if 0 < lib_ordinal <= cmd.imports_count:
                            imp_ordinal, weak_import, name_offset, imp_addend = cmd.imports[lib_ordinal - 1]
                            symbol = self.__get_chained_fixups_symbol(cmd, chain_data, name_offset)
                            addend = addend + imp_addend
                            dylib = self.get_chained_dylib_by_ordinal(imp_ordinal)
                            if dylib == None:
                                print('Warning: chained bind {:s} uses unsupported library ordinal {:d}'.format(symbol, imp_ordinal))
                        else:
                            print('Warning: chained bind with out of range ordinal {:d} at 0x{:X}'.format(
                                lib_ordinal, segment.vmaddr + seg_off))
                        fixup_function(seg_idx, seg_off, segment.vmaddr + seg_off, 0, dylib, symbol, addend)
                    else:
                        #user space formats store the absolute unslid vmaddr, the kernel and
                        #firmware formats an offset relative to the preferred segment address
                        target_vmaddr = starts.rebase_target(entry['target'])
                        fixup_function(seg_idx, seg_off, segment.vmaddr + seg_off, target_vmaddr, None, None, 0)

                    if entry['next'] == 0:
                        break
                    next_off = next_off + entry['next'] * ptr_size
                    if next_off >= starts.page_size * 4:
                        break

    def __chained_fixups_bind_pass1(self, seg_idx, seg_off, ptr_vmaddr, target_vmaddr, dylib, symbol, addend):
        #build the import table out of the chained fixup bind entries
        if symbol == None or dylib == None:
            return
        dylib.append_symbol(symbol)

    def __chained_fixups_bind_pass2(self, seg_idx, seg_off, ptr_vmaddr, target_vmaddr, dylib, symbol, addend):
        #write the resolved vmaddr back into the in memory copy of the section
        if symbol != None:
            target = self.get_virtual_map_addr(symbol)
            if target == None:
                return
            #TODO: the addend of a chained bind is not applied, the virtual section
            #data structure would have to carry it like the dyld_info path does
        else:
            target = target_vmaddr

        section, position = self.get_section_position(seg_idx, seg_off)
        if section == None or section.data == None:
            return

        if self.__is_64bit_cpu == True:
            length = 8
            addr_str = struct.pack(self.__endian_str + 'Q', target)
        else:
            length = 4
            addr_str = struct.pack(self.__endian_str + 'L', target)

        if position < 0 or position + length > len(section.data):
            return

        section.data = section.data[0 : position] + addr_str + section.data[position + length :]
        #print '0x{:X} chained fixup to 0x{:X}'.format(segment.vmaddr + seg_off, target)

    #Load binding information and build up a binding table which is a list of vmaddr to imported symbol mapping
    #This is a simple implementation
    #Many Object-C data structure are fixed up based on binding information. The binding table must be loaded before analyzing and dumping Object-C data.
    def __build_bind_info(self, bind_off, bind_size, bind_function):
        self.__fd.seek(self.__mh_offset + bind_off)
        bind_data = self.__fd.read(bind_size)
        library = None
        bind_item = []
        bind_list = []

        i = 0
        #Deal with bind command without set dylib ordinal
        lib_ordinal = 1
        value = None
        len = None
        symbol = None
        type = None
        addend = 0
        seg_idx = None
        seg_off = None
        addr = None
        count = None
        skip = None
        while i < bind_size:
            byte = bind_data[i]
            opcode = byte & DYLD_INFO_BIND_OPCODE.OPCODE_MASK.value
            opcode = DYLD_INFO_BIND_OPCODE(opcode)
            imm = byte & DYLD_INFO_BIND_OPCODE.IMMEDIATE_MASK.value

            debug_str = '[0x{:x}] 0x{:x}:'.format(i, byte)
            i = i + 1
            if opcode == DYLD_INFO_BIND_OPCODE.DONE:

                debug_str = debug_str + 'bind done'
                #print debug_str

                return
                
            elif opcode == DYLD_INFO_BIND_OPCODE.SET_DYLIB_ORDINAL_IMM:
                lib_ordinal = imm
                
                debug_str = debug_str + 'set library oridinal imm: {:d}'.format(lib_ordinal)
                #print debug_str
                
            elif opcode == DYLD_INFO_BIND_OPCODE.SET_DYLIB_ORDINAL_ULEB:
                value, len = leb128.decode_uleb128(bind_data[i:bind_size:], bind_size - i)
                lib_ordinal = value
                i = i + len
                
                debug_str = debug_str + 'set library oridinal uleb: 0x{:x}'.format(lib_ordinal)
                #print debug_str
                
            elif opcode == DYLD_INFO_BIND_OPCODE.SET_DYLIB_SPECIAL_IMM:
                #Have no idea about how to handle negative or zero library ordinal
                #So print and raise an exception here
                if imm != 0:
                    lib_ordinal = imm | DYLD_INFO_BIND_OPCODE.OPCODE_MASK.value
                else:
                    lib_ordinal = imm

                debug_str = debug_str + 'set library oridinal special imm: 0x{:x}'.format(lib_ordinal)
                #print debug_str
                raise UnsupportBindOpcode(byte)
                    
            elif opcode == DYLD_INFO_BIND_OPCODE.SET_SYMBOL_TRAILING_FLAGS_IMM:
                symbol_bytes = b''
                while bind_data[i] != 0:
                    symbol_bytes = symbol_bytes + bind_data[i:i+1]
                    i = i + 1
                i = i + 1
                symbol = bytes_to_str(symbol_bytes)

                debug_str = debug_str + 'set symbol imm: 0x{:x}, {:s}'.format(imm, symbol)
                #print debug_str
                
            elif opcode == DYLD_INFO_BIND_OPCODE.SET_TYPE_IMM:
                type = imm

                debug_str = debug_str + 'set type imm: 0x{:x}'.format(type)
                #print debug_str

                if DYLD_INFO_BIND_TYPE(type) != DYLD_INFO_BIND_TYPE.POINTER:
                    raise UnsupportBindOpcode(byte)
                
            elif opcode == DYLD_INFO_BIND_OPCODE.SET_ADDEND_SLEB:
                #TODO: Add support for non zero addend
                #The virtual section data structure need to be revised
                addend, len = leb128.decode_sleb128(bind_data[i:bind_size:], bind_size - i)
                i = i + len

                debug_str = debug_str + 'set addend sleb: 0x{:x}'.format(addend)
                #print debug_str

                #raise UnsupportBindOpcode(byte)
                
            elif opcode == DYLD_INFO_BIND_OPCODE.SET_SEGMENT_AND_OFFSET_ULEB:
                seg_idx = imm
                seg_off, len = leb128.decode_uleb128(bind_data[i:bind_size:], bind_size - i)
                i = i + len

                debug_str = debug_str + 'set segment: {:d} and offset 0x{:x}'.format(seg_idx, seg_off)
                #print debug_str
                
            elif opcode == DYLD_INFO_BIND_OPCODE.ADD_ADDR_ULEB:
                addr, len = leb128.decode_uleb128(bind_data[i:bind_size:], bind_size - i)
                i = i + len
                #it's actually signed long long
                if addr & 0x8000000000000000:
                    addr = -((addr - 1) ^ 0xFFFFFFFFFFFFFFFF)
                seg_off = seg_off + addr

                debug_str = debug_str + 'add addr uleb: 0x{:x}'.format(seg_off)
                #print debug_str
                
            elif opcode == DYLD_INFO_BIND_OPCODE.DO_BIND:
                bind_function(seg_idx, seg_off, type, lib_ordinal, addend, symbol)
                if self.__is_64bit_cpu == True:
                    seg_off = seg_off + 8
                else:
                    seg_off = seg_off + 4

                debug_str = debug_str + 'do bind, offset is now: 0x{:x}'.format(seg_off)
                #print debug_str
                
            elif opcode == DYLD_INFO_BIND_OPCODE.DO_BIND_ADD_ADDR_ULEB:
                bind_function(seg_idx, seg_off, type, lib_ordinal, addend, symbol)
                if self.__is_64bit_cpu == True:
                    seg_off = seg_off + 8
                else:
                    seg_off = seg_off + 4
                
                addr, len = leb128.decode_uleb128(bind_data[i:bind_size:], bind_size - i)
                if addr & 0x8000000000000000:
                    addr = -((addr - 1) ^ 0xFFFFFFFFFFFFFFFF)
                i = i + len
                seg_off = seg_off + addr

                debug_str = debug_str + 'do bind add addr uleb, offset is now: 0x{:x}'.format(seg_off)
                #print debug_str
                
            elif opcode == DYLD_INFO_BIND_OPCODE.DO_BIND_ADD_ADDR_IMM_SCALED:
                bind_function(seg_idx, seg_off, type, lib_ordinal, addend, symbol)
                if self.__is_64bit_cpu == True:
                    seg_off = seg_off + (imm + 1)* 8
                else:
                    seg_off = seg_off + (imm + 1) * 4

                debug_str = debug_str + 'do bind add addr imm scaled, offset is now: 0x{:x}'.format(seg_off)
                #print debug_str
                
            elif opcode == DYLD_INFO_BIND_OPCODE.DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                count, len = leb128.decode_uleb128(bind_data[i:bind_size:], bind_size - i)
                i = i + len
                skip, len = leb128.decode_uleb128(bind_data[i:bind_size:], bind_size - i)
                i = i + len

                for j in range(count):
                    bind_function(seg_idx, seg_off, type, lib_ordinal, addend, symbol)
                    if self.__is_64bit_cpu == True:
                        seg_off = seg_off + skip + 8
                    else:
                        seg_off = seg_off + skip + 4

                debug_str = debug_str + 'do bind ulbe times ({:d}) skipping uleb ({:d}), offset is now: 0x{:x}'.format(count, skip, seg_off)
                #print debug_str
            else:
                raise UnsupportBindOpcode(byte)
        #bind commands without end
        print('bind commands without end')
        return

    #Search for segment  LOAD_COMMAND_SEGMENT or LOAD_COMMAND_SEGMENT64 with segment index
    #Generally __ZEROPAGE is indexed by 0, __TEXT by 1, __DATA by 2 and __LINKEDIT by 3
    def get_segment(self, seg_idx):
        if seg_idx == None or seg_idx < 0 or seg_idx >= len(self.__segments):
            return None
        return self.__segments[seg_idx]
    
    #Return the section of a segment that contains seg_off, an offset relative to the
    #beginning of the segment. The sections of a segment are not necessarily contiguous
    #and a segment does not have to start with a section, so the offset of every section
    #within the segment is what decides, not the sum of the section sizes.
    def get_section_by_addr(self, seg_idx, seg_off):
        segment = self.get_segment(seg_idx)
        if segment == None:
            return None
        for section in segment.sections:
            section_seg_off = section.offset - segment.offset
            if section_seg_off <= seg_off < section_seg_off + section.vmsize:
                return section
        return None

    #Offset of a segment relative position inside the data buffer of its section
    def get_section_position(self, seg_idx, seg_off):
        segment = self.get_segment(seg_idx)
        section = self.get_section_by_addr(seg_idx, seg_off)
        if segment == None or section == None:
            return None, None
        return section, seg_off - (section.offset - segment.offset)

    def __bind_pass1(self, seg_idx, seg_off, type, lib_ordinal, addend, symbol):
        dylib = self.get_dylib_by_ordinal(lib_ordinal)
        if dylib == None:
            print('Warning: bind {:s} refers to unknown library ordinal {:d}'.format(symbol, lib_ordinal))
            return
        dylib.append_symbol(symbol)
        
    def __bind_pass2(self, seg_idx, seg_off, type, lib_ordinal, addend, symbol):
        section, position = self.get_section_position(seg_idx, seg_off)
        if section == None or section.data == None:
            return
        symbol_addr = self.get_virtual_map_addr(symbol)
        if symbol_addr == None:
            return

        if self.__is_64bit_cpu == True:
            length = 8
            addr_str = struct.pack(self.__endian_str + 'Q', symbol_addr)
        else:
            length = 4
            addr_str = struct.pack(self.__endian_str + 'L', symbol_addr)

        if position < 0 or position + length > len(section.data):
            return

        #TODO: addend
        data = section.data[0 : position] + addr_str + section.data[position + length:]
        section.data = data
        #print '0x{:X} binding to 0x{:X}:{:s}+{:d}'.format(segment.vmaddr + seg_off, symbol_addr, symbol, addend)

    def dump_import_table(self):
        for dylib in self.__dylibs:
            print(dylib.name)
            for symbol in dylib.symbols:
                print('    ', symbol)

    def __build_virtual_section(self):
        if len(self.__segments) == 0:
            return []
        segment = self.__segments[-1]
        addr = segment.vmaddr + segment.vmsize

        vsec = []
        for dylib in self.__dylibs:
            for symbol in dylib.symbols:
                vmap = VirtualMap(addr, symbol)
                vsec.append(vmap)
                if self.__is_64bit_cpu == True:
                    addr = addr + 8
                else:
                    addr = addr + 4
        return vsec

    def is_virtual_section_addr(self, addr):
        #a binary without any imported symbol has an empty virtual section
        if len(self.__virtual_section) == 0:
            return False
        return addr >= self.__virtual_section[0].addr
        
    def get_virtual_map_addr(self, symbol):
        for vmap in self.__virtual_section:
            if symbol == vmap.symbol:
                return vmap.addr

    def get_virtual_map_symbol(self, addr):
        if self.is_virtual_section_addr(addr):
            if self.__is_64bit_cpu == True:
                idx = (addr - self.__virtual_section[0].addr) // 8
            else:
                idx = (addr - self.__virtual_section[0].addr) // 4
            if idx < len(self.__virtual_section):
                return self.__virtual_section[idx].symbol
        return None
        
    def dump_virtual_section(self):
        for vmap in self.__virtual_section:
            print('0x{:X}:{:s}'.format(vmap.addr, vmap.symbol))
    
    #Search a section with segment name and section name
    def get_section_by_name(self, seg_name, sec_name):
        for segment in self.__segments:
            if seg_name == segment.name:
                for section in segment.sections:
                    if sec_name == section.name:
                        return section
        return None

    def get_objc2_ivar_layout(self, vmaddr):
        section = self.get_section_by_name('__TEXT', '__objc_classname')
        assert vmaddr < (section.vmaddr + section.vmsize)

        position = vmaddr - section.vmaddr
        ivar_layout = section.data[position]
        return ivar_layout
        
    def get_objc2_cls_name(self, vmaddr):
        section = self.get_section_by_name('__TEXT', '__objc_classname')
        assert vmaddr < (section.vmaddr + section.vmsize)
        
        position = vmaddr - section.vmaddr
        c_str = b''
        
        while True:
            c = section.data[position]
            position = position + 1
            if c == 0:
                break
            c_str = c_str + bytes((c,))
        return bytes_to_str(c_str)
    
    def get_objc2_method_name(self, vmaddr):
        section = self.get_section_by_name('__TEXT', '__objc_methname')
        assert vmaddr < (section.vmaddr + section.vmsize)

        position = vmaddr - section.vmaddr
        i = 0
        c_str = b''
        while True:
            c = section.data[position]
            position = position + 1
            if c == 0:
                break
            c_str = c_str + bytes((c,))
        return bytes_to_str(c_str)

    def get_objc2_method_type(self, vmaddr):
        section = self.get_section_by_name('__TEXT', '__objc_methtype')
        assert vmaddr < (section.vmaddr + section.vmsize)

        position = vmaddr - section.vmaddr
        i = 0
        c_str = b''
        while True:
            c = section.data[position]
            position = position + 1
            if c == 0:
                break
            c_str = c_str + bytes((c,))
        return bytes_to_str(c_str)

    '''
    struct objc2_meth
    {
        vmaddr sel_ptr;
        vmaddr type_ptr;
        vmaddr imp_ptr;
    }
    struct objc2_meth_list
    {
        unsigned long entry_size;
        unsigned long entry_count;
        struct objc2_meth first;
    }
    '''
    def get_objc2_methods(self, vmaddr):
        section = self.get_section_by_name('__DATA', '__objc_const')
        assert vmaddr < (section.vmaddr + section.vmsize)

        position = vmaddr - section.vmaddr
        entry_size, entry_count = struct.unpack(self.__endian_str + 'LL', section.data[position: position + 8:])
        position = position + 8

        method_list = []
        for i in range(entry_count):
            if self.__is_64bit_cpu == True:
                sel_ptr, type_ptr, imp_ptr = struct.unpack(self.__endian_str + 'QQQ', section.data[position: position + entry_size:])
            else:
                sel_ptr, type_ptr, imp_ptr = struct.unpack(self.__endian_str + 'LLL', section.data[position: position + entry_size:])
            position = position + entry_size
            
            meth_name = self.get_objc2_method_name(sel_ptr)
            meth_type = self.get_objc2_method_type(type_ptr)
            imp_addr = '0x{:X}'.format(imp_ptr)
            
            objc2_meth = ObjC2Method(meth_name, meth_type, imp_addr)
            method_list.append(objc2_meth)

        return method_list

    def get_objc2_protocols(self, vmaddr):
        pass

    def get_objc2_ivar_offset(self, vmaddr):
        section = self.get_section_by_name('__DATA', '__objc_ivar')
        assert vmaddr < (section.vmaddr + section.vmsize)

        position = vmaddr - section.vmaddr
        offset, = struct.unpack(self.__endian_str + 'L', section.data[position: position + 4])
        return offset
        
    '''
    struct objc2_ivar
    {
        vmaddr offset_ptr;
        vmaddr name_ptr;
        vmaddr type_ptr;
        unsigned long alignment;
        unsigned long size;
    }
    struct objc2_ivar_list
    {
        unsigned long entry_size;
        unsigned long entry_count;
        struct objc2_ivar first;
    }
    ''' 
    def get_objc2_ivars(self, vmaddr):
        section = self.get_section_by_name('__DATA', '__objc_const')
        assert vmaddr < (section.vmaddr + section.vmsize)

        position = vmaddr - section.vmaddr
        entry_size, entry_count = struct.unpack(self.__endian_str + 'LL', section.data[position : position + 8])
        position = position + 8

        ivar_list = []
        for i in range(entry_count):
            if self.__is_64bit_cpu == True:
                offset_ptr, name_ptr, type_ptr, alignment, size = struct.unpack(self.__endian_str + 'QQQLL', section.data[position : position + entry_size])
            else:
                offset_ptr, name_ptr, type_ptr, alignment, size = struct.unpack(self.__endian_str + 'LLLLL', section.data[position : position + entry_size])
            position = position + entry_size

            offset = self.get_objc2_ivar_offset(offset_ptr)
            meth_name = self.get_objc2_method_name(name_ptr)
            meth_type = self.get_objc2_method_type(type_ptr)

            objc2_ivar = ObjC2IVar(offset, meth_name, meth_type, alignment, size)
            
            ivar_list.append(objc2_ivar)

        return ivar_list

    def get_cstring(self, vmaddr):
        section = self.get_section_by_name('__TEXT', '__cstring')
        assert vmaddr < (section.vmaddr + section.vmsize)

        position = vmaddr - section.vmaddr
        c_str = b''
        while True:
            c = section.data[position]
            position = position + 1
            if c == 0:
                break
            c_str = c_str + bytes((c,))
        return bytes_to_str(c_str)
    
    '''
    struct objc2_property
    {
        vmaddr name_ptr;
        vmaddr attr_ptr;
    };

    struct objc2_prop_list
    {
        unsigned long entry_size;
        unsigned long entry_count;
        struct objc2_prop first;
    };
    '''
    def get_objc2_properties(self, vmaddr):
        section = self.get_section_by_name('__DATA', '__objc_const')
        assert vmaddr < (section.vmaddr + section.vmsize)

        position = vmaddr - section.vmaddr
        entry_size, entry_count = struct.unpack(self.__endian_str + 'LL', section.data[position : position + 8])
        position = position + 8

        prop_list = []
        for i in range(entry_count):
            if self.__is_64bit_cpu == True:
                name_ptr, attr_ptr = struct.unpack(self.__endian_str + 'QQ', section.data[position : position + entry_size])
            else:
                name_ptr, attr_ptr = struct.unpack(self.__endian_str + 'LL', section.data[position : position + entry_size])
            position = position + entry_size

            name = self.get_cstring(name_ptr)
            attr = self.get_cstring(attr_ptr)
            objc2_property = ObjC2Property(name, attr)

            prop_list.append(objc2_property)
            
        return prop_list
        
    '''
    struct objc2_class_ro {
        uint32_t flags;
        uint32_t instanceStart;
        uint32_t instanceSize;
        uint32_t reserved; // *** this field does not exist in the 32-bit version ***
        vmaddr ivar_layout_ptr;
        vmaddr cls_name_ptr;
        vmaddr base_methods_ptr;
        vmaddr base_protocols_ptr;
        vmaddr ivars_ptr;
        vmaddr weak_ivar_layout_ptr;
        vmaddr base_properties_ptr;
    };
    '''
    def __build_objc2_cls_ro(self, vmaddr):
        section = self.get_section_by_name('__DATA', '__objc_const')
        assert vmaddr < (section.vmaddr + section.vmsize)

        position = vmaddr - section.vmaddr
        flags, inst_start, inst_size = struct.unpack(self.__endian_str + 'LLL', section.data[position : position + 12])

        if self.__is_64bit_cpu == True:
            #class_ro is 4 uint32 (flags, instanceStart, instanceSize, reserved) followed by
            #4 bytes of padding and then the 7 pointers, 72 bytes in total. The reserved word
            #and the pointers are read separately on purpose: struct aligns every field of a
            #'<' format to its own size, so a mixed 'LQQQQQQQ' format places the second Q at
            #offset 12 instead of 8 and reports a size of 60 instead of 64.
            reserved, = struct.unpack(self.__endian_str + 'L', section.data[position + 12 : position + 16])
            ivar_layout_ptr, cls_name_ptr, base_methods_ptr, base_protocols_ptr, ivars_ptr, weak_ivar_layout_ptr, base_properties_ptr = \
                struct.unpack(self.__endian_str + 'QQQQQQQ', section.data[position + 16 : position + 72])
            position = position + 72
        else:
            #the 32-bit class_ro has no reserved field and no padding, 28 bytes in total
            ivar_layout_ptr, cls_name_ptr, base_methods_ptr, base_protocols_ptr, ivars_ptr, weak_ivar_layout_ptr, base_properties_ptr = \
                struct.unpack(self.__endian_str + 'LLLLLLL', section.data[position + 12 : position + 40])
            reserved = None
            position = position + 40
        

        if ivar_layout_ptr != 0:
            ivar_layout = self.get_objc2_ivar_layout(ivar_layout_ptr)
        else:
            ivar_layout = None

        if cls_name_ptr != 0:
            cls_name = self.get_objc2_cls_name(cls_name_ptr)
        else:
            cls_name = None

        if base_methods_ptr != 0:
            methods = self.get_objc2_methods(base_methods_ptr)
        else:
            methods = None

        if base_protocols_ptr != 0:
            self.get_objc2_protocols(base_protocols_ptr)

        if ivars_ptr != 0:
            ivars = self.get_objc2_ivars(ivars_ptr)
        else:
            ivars = None

        if weak_ivar_layout_ptr != 0:
            weak_ivar_layout = self.get_objc2_ivar_layout(weak_ivar_layout_ptr)
        else:
            weak_ivar_layout = None

        if base_properties_ptr != 0:
            properties = self.get_objc2_properties(base_properties_ptr)
        else:
            properties = None

        return ObjC2ClassRO(flags, inst_start, inst_size, ivar_layout, cls_name, methods, ivars, weak_ivar_layout, properties, reserved)
    
    '''
    struct objc2_class {
        vmaddr isa_ptr;
        vmaddr superclass_ptr;
        vmaddr cache_ptr;
        vmaddr vtable_ptr;
        vmaddr data_ptr; //objc2_class_ro
    }
    
    '''
    def __build_objc2_cls(self, vmaddr):
        section = self.get_section_by_name('__DATA', '__objc_data')
        assert vmaddr < (section.vmaddr + section.vmsize)

        if vmaddr in self.__objc2_cls_stack:
            return None
        else:
            self.__objc2_cls_stack.append(vmaddr)
        
        position = vmaddr - section.vmaddr
        if self.__is_64bit_cpu == True:
            isa_ptr, superclass_ptr, cache_ptr, vtable_ptr, data_ptr = \
                struct.unpack(self.__endian_str + 'QQQQQ', section.data[position : position + 40])
        else:
            isa_ptr, superclass_ptr, cache_ptr, vtable_ptr, data_ptr = \
                struct.unpack(self.__endian_str + 'LLLLL', section.data[position : position + 20])

        objc2_cls_ro = self.__build_objc2_cls_ro(data_ptr)
        objc2_class = ObjC2Class(vmaddr, objc2_cls_ro)
        self.__resloved_objc2_cls_list.append(objc2_class)

        isa = None
        if self.is_virtual_section_addr(isa_ptr):
            isa_name = self.get_virtual_map_symbol(isa_ptr)
        elif isa_ptr != 0:
            isa = self.__build_objc2_cls(isa_ptr)
            if isa == None:
                for resloved_cls in self.__resloved_objc2_cls_list:
                    if isa_ptr == resloved_cls.vmaddr:
                        isa_name = resloved_cls.name
                        break
            else:
                isa_name = isa.name
        else:
            isa_name = '{:d}'.format(isa_ptr)

        objc2_class.isa = isa
        objc2_class.isa_name = isa_name

        superclass = None
        if self.is_virtual_section_addr(superclass_ptr):
            superclass_name = self.get_virtual_map_symbol(superclass_ptr)
        elif superclass_ptr != 0:
            superclass = self.__build_objc2_cls(superclass_ptr)
            if superclass == None:
                for resloved_cls in self.__resloved_objc2_cls_list:
                    if superclass_ptr == resloved_cls.vmaddr:
                        superclass_name = resloved_cls.name
                        break
            else:
                superclass_name = superclass.name
        else:
            superclass_name = '{:d}'.format(superclass_ptr)

        objc2_class.superclass = superclass
        objc2_class.superclass_name = superclass_name
                
        #an address of the virtual section that cannot be mapped back to a symbol is
        #printed as a plain address instead of leaving the field empty
        if self.is_virtual_section_addr(cache_ptr):
            cache_name = self.get_virtual_map_symbol(cache_ptr)
        else:
            cache_name = None
        if cache_name == None:
            cache_name = '0x{:X}'.format(cache_ptr)
        objc2_class.cache_name = cache_name

        if self.is_virtual_section_addr(vtable_ptr):
            vtable_name = self.get_virtual_map_symbol(vtable_ptr)
        else:
            vtable_name = None
        if vtable_name == None:
            vtable_name = '0x{:X}'.format(vtable_ptr)
        objc2_class.vtable_name = vtable_name

        self.__objc2_cls_stack.pop()
        return objc2_class
        
    def __build_objc2_clslist(self):
        section = self.get_section_by_name('__DATA', '__objc_classlist')
        if section == None:
            return []

        if self.__is_64bit_cpu == True:
            n_cls = section.vmsize // 8
        else:
            n_cls = section.vmsize // 4

        cls_list = []
        position = 0
        for i in range(n_cls):
            if self.__is_64bit_cpu == True:
                objc2_cls_ptr, = struct.unpack(self.__endian_str + 'Q', section.data[position : position + 8 :])
                position = position + 8
            else:
                objc2_cls_ptr, = struct.unpack(self.__endian_str + 'L', section.data[position : position + 4 :])
                position = position + 4
            #an empty or foreign entry must not be walked as a class object
            if objc2_cls_ptr == 0 or not self.is_objc2_class_addr(objc2_cls_ptr):
                continue
            objc2_cls = self.__build_objc2_cls(objc2_cls_ptr)
            cls_list.append(objc2_cls)

        return cls_list

    def __build_objc2_nlclslist(self):
        section = self.get_section_by_name('__DATA', '__objc_nlclslist')
        if section == None:
            return []

        if self.__is_64bit_cpu == True:
            n_cls = section.vmsize // 8
        else:
            n_cls = section.vmsize // 4

        cls_list = []
        position = 0
        for i in range(n_cls):
            if self.__is_64bit_cpu == True:
                objc2_cls_ptr, = struct.unpack(self.__endian_str + 'Q', section.data[position : position + 8 :])
                position = position + 8
            else:
                objc2_cls_ptr, = struct.unpack(self.__endian_str + 'L', section.data[position : position + 4 :])
                position = position + 4
            #an empty or foreign entry must not be walked as a class object
            if objc2_cls_ptr == 0 or not self.is_objc2_class_addr(objc2_cls_ptr):
                continue
            objc2_cls = self.__build_objc2_cls(objc2_cls_ptr)
            cls_list.append(objc2_cls)

        return cls_list

    def __build_objc2_protolist(self):
        section = self.get_section_by_name('__DATA', '__objc_protolist')
        if self.__is_64bit_cpu == True:
            n_proto = section.vmsize // 8
        else:
            n_proto = section.vmsize // 4

        proto_list = []
        #TODO

    def dump_objc_classlist(self):
        for objc_class in self.__objc_classlist:
            objc_class.dump()

    def dump_objc_nlclslist(self):
        for objc_class in self.__objc_nlclslist:
            objc_class.dump()

    def dump_section_objc_selrefs(self):
        section = self.get_section_by_name('__DATA', '__objc_selrefs')
        if section == None:
            print('section __DATA,__objc_selrefs not found')
            return

        if self.__is_64bit_cpu == True:
            ref_size = 8
        else:
            ref_size = 4
            
        nrefs = section.vmsize // ref_size

        address = section.vmaddr
        for i in range(nrefs):
            position = address - section.vmaddr
            if self.__is_64bit_cpu == True:
                ref, = struct.unpack(self.__endian_str + 'Q', section.data[position : position + ref_size])
            else:
                ref, = struct.unpack(self.__endian_str + 'L', section.data[position : position + ref_size])

            method_name = self.get_objc2_method_name(ref)
            print('0x{:X}: __objc_methname(\'{:s}\')'.format(address, method_name))
            address = address + ref_size

    #True if vmaddr points into the __objc_data section, where the class objects live
    def is_objc2_class_addr(self, vmaddr):
        section = self.get_section_by_name('__DATA', '__objc_data')
        if section == None:
            return False
        return section.vmaddr <= vmaddr < (section.vmaddr + section.vmsize)

    def get_objc_class_ref(self, vmaddr):
        for objc_class in self.__objc_classlist:
            if vmaddr == objc_class.vmaddr:
                return objc_class
        
        for objc_class in self.__objc_nlclslist:
            if vmaddr == objc_class.vmaddr:
                return objc_class

        return None
        
    def dump_section_objc_classrefs(self):
        section = self.get_section_by_name('__DATA', '__objc_classrefs')
        if section == None:
            print('section __DATA,__objc_classrefs not found')
            return

        if self.__is_64bit_cpu == True:
            ref_size = 8
        else:
            ref_size = 4
            
        nrefs = section.vmsize // ref_size

        address = section.vmaddr
        for i in range(nrefs):
            position = address - section.vmaddr
            if self.__is_64bit_cpu == True:
                ref, = struct.unpack(self.__endian_str + 'Q', section.data[position : position + ref_size])
            else:
                ref, = struct.unpack(self.__endian_str + 'L', section.data[position : position + ref_size])

            if self.is_virtual_section_addr(ref):
                class_name = self.get_virtual_map_symbol(ref)
            else:
                objc_class = self.get_objc_class_ref(ref)
                class_name = objc_class.name
            print('0x{:X}: {:s}'.format(address, class_name))
            address = address + ref_size

    def dump_section_objc_superrefs(self):
        section = self.get_section_by_name('__DATA', '__objc_superrefs')
        if section == None:
            print('section __DATA,__objc_superrefs not found')
            return

        if self.__is_64bit_cpu == True:
            ref_size = 8
        else:
            ref_size = 4
            
        nrefs = section.vmsize // ref_size

        address = section.vmaddr
        for i in range(nrefs):
            position = address - section.vmaddr
            if self.__is_64bit_cpu == True:
                ref, = struct.unpack(self.__endian_str + 'Q', section.data[position : position + ref_size])
            else:
                ref, = struct.unpack(self.__endian_str + 'L', section.data[position : position + ref_size])

            if self.is_virtual_section_addr(ref):
                class_name = self.get_virtual_map_symbol(ref)
            else:
                objc_class = self.get_objc_class_ref(ref)
                class_name = objc_class.name
            print('0x{:X}: {:s}'.format(address, class_name))
            address = address + ref_size

    def dump_section_objc_ivar(self):
        section = self.get_section_by_name('__DATA', '__objc_ivar')
        if section == None:
            print('section __DATA,__objc_ivar not found')
            return

        ivar_size = 4
            
        nivar = section.vmsize // ivar_size

        address = section.vmaddr
        for i in range(nivar):
            position = address - section.vmaddr
            ivar, = struct.unpack(self.__endian_str + 'L', section.data[position : position + ivar_size])

            print('0x{:X}: 0x{:X}'.format(address, ivar))
            address = address + ivar_size

    '''
    struct __NSConstantStringImpl
    {
        vmaddr isa;
        unsigned long flags;
        vmaddr str;
        unsigned long length;
    }
    
    struct __NSConstantStringImpl64
    {
        vmaddr isa;
        unsigned long long flags;
        vmaddr str;
        unsigned long long length;
    }
    '''
    def dump_section_cfstring(self):
        section = self.get_section_by_name('__DATA', '__cfstring')
        if section == None:
            print('section __DATA,__cfstring not found')
            return

        if self.__is_64bit_cpu == True:
            cfstring_size = 32
        else:
            cfstring_size = 16
            
        ncfstring = section.vmsize // cfstring_size

        address = section.vmaddr
        for i in range(ncfstring):
            position = address - section.vmaddr
            if self.__is_64bit_cpu == True:
                isa, flags, str, length = struct.unpack(self.__endian_str + 'QQQQ', section.data[position : position + cfstring_size])
            else:
                isa, flags, str, length = struct.unpack(self.__endian_str + 'LLLL', section.data[position : position + cfstring_size])

            if self.is_virtual_section_addr(isa):
                isa_name = self.get_virtual_map_symbol(isa)
            else:
                isa_name = None
            if isa_name == None:
                isa_name = '0x{:X}'.format(isa)

            c_str = self.get_cstring(str)

            print('0x{:X}: __CFString<{:s}, 0x{:X}, \'{:s}\', {:d}>'.format(address, isa_name, flags, c_str, length))
            address = address + cfstring_size

def main():
    from optparse import OptionParser

    parser = OptionParser(usage='usage: %prog [options] file', version='%prog 0.01')
    
    parser.add_option('-a', '--arch', action='store', dest='arch', \
        type='choice', choices=['arm', 'aarch64', 'i386', 'x86_64'], default='aarch64', help='specify an arch to dump, aarch64 is specified by default, applicable only for FAT Mach-O file')

    parser.add_option('-l', '--all', action='store_true', dest='dump_all', default=False, help='dump all')
    parser.add_option('-c', '--classlist', action='store_true', dest='dump_clslist', default=False, help='dump section __objc_classlist')
    parser.add_option('-n', '--nlclslist', action='store_true', dest='dump_nlclslist', default=False, help='dump section __objc_nlclslist')
    parser.add_option('-s', '--selrefs', action='store_true', dest='dump_selrefs', default=False, help='dump section __objc_selrefs')
    parser.add_option('-r', '--classrefs', action='store_true', dest='dump_classrefs', default=False, help='dump section __objc_classrefs')
    parser.add_option('-u', '--superrefs', action='store_true', dest='dump_superrefs', default=False, help='dump section __objc_superrefs')
    parser.add_option('-i', '--ivar', action='store_true', dest='dump_ivar', default=False, help='dump section __objc_ivar')
    parser.add_option('-f', '--cfstring', action='store_true', dest='dump_cfstring', default=False, help='dump section __cfstring')
    parser.add_option('-m', '--import_table', action='store_true', dest='dump_import_table', default=False, help='dump all imported symbols')
    parser.add_option('-v', '--virtual_section', action='store_true', dest='dump_vsection', default=False, help='dump virtual section for dynamic binding')
    
    options, args = parser.parse_args()
    if len(args) != 1:
        parser.print_help()
        sys.exit(0)
    
    file = args[0]

    arch = None
    if options.arch == 'aarch64':
        arch = MACH_O_CPU_TYPE.ARM64
    elif options.arch == 'arm':
        arch = MACH_O_CPU_TYPE.ARM
    elif options.arch == 'i386':
        arch = MACH_O_CPU_TYPE.I386
    elif options.arch == 'x86_64':
        arch = MACH_O_CPU_TYPE.X86_64
    else:
        print('Unknown arch selected, fallback to aarch64')
        arch = MACH_O_CPU_TYPE.ARM64

    if options.dump_all == True:
        options.dump_clslist = True
        options.dump_nlclslist = True
        options.dump_selrefs = True
        options.dump_classrefs = True
        options.dump_superrefs = True
        options.dump_ivar = True
        options.dump_cfstring = True
        options.dump_import_table = True
        options.dump_vsection = True
    
    fd = open(file, 'rb')
    try:
        mach_o_anylyzer = MachOAnalyzer(fd, arch)
    except UnknownMagic as e:
        print('Unknow magic:' + str(e))
        fd.close()
        sys.exit(0)

    if options.dump_clslist:
        print('--------------__objc_classlist--------------')
        mach_o_anylyzer.dump_objc_classlist()

    if options.dump_nlclslist:
        print('--------------__objc_nlclslist--------------')
        mach_o_anylyzer.dump_objc_nlclslist()

    if options.dump_selrefs:
        print('---------------__objc_selrefs---------------')
        mach_o_anylyzer.dump_section_objc_selrefs()

    if options.dump_classrefs:
        print('--------------__objc_classrefs--------------')
        mach_o_anylyzer.dump_section_objc_classrefs()

    if options.dump_superrefs:
        print('--------------__objc_superrefs--------------')
        mach_o_anylyzer.dump_section_objc_superrefs()

    if options.dump_ivar:
        print('----------------__objc_ivar-----------------')
        mach_o_anylyzer.dump_section_objc_ivar()

    if options.dump_cfstring:
        print('-----------------__cfstring-----------------')
        mach_o_anylyzer.dump_section_cfstring()

    if options.dump_import_table:
        print('----------------import_table----------------')
        mach_o_anylyzer.dump_import_table()

    if options.dump_vsection:
        print('---------------virtual_section--------------')
        mach_o_anylyzer.dump_virtual_section()

    fd.close()

if __name__ == '__main__':
    main()
