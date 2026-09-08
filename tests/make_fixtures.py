'''
Build small synthetic arm64 Mach-O binaries used by the unit tests.

Two flavours are produced out of the very same ObjC layout:

    * fixture_chained_fixups.bin  uses LC_DYLD_CHAINED_FIXUPS (what modern Xcode emits)
    * fixture_dyld_info.bin       uses LC_DYLD_INFO_ONLY (the classic opcode stream)

Both contain one class MyClass which derives from the imported _OBJC_CLASS_$_NSObject,
one method `testMethod` and one ivar `_myField`. They are not runnable images, they
only carry the sections this dumper reads.
'''
import os
import struct

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_ARM64_ALL = 0
MH_EXECUTE = 2

LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC
LC_DYLD_INFO_ONLY = 0x80000022
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_BUILD_VERSION = 0x32
LC_UUID = 0x1B

S_CSTRING_LITERALS = 0x2
S_MOD_INIT_FUNC_POINTERS = 0x9
S_REGULAR = 0x0

BASE = 0x100000000
TEXT_FILEOFF = 0x1000
TEXT_SIZE = 0x1000
DATA_FILEOFF = 0x2000
#__objc_data runs from 0x18 to 0x198 of __DATA, the sections are contiguous
DATA_VMSIZE = 0x178
LINKEDIT_FILEOFF = TEXT_FILEOFF + TEXT_SIZE + DATA_VMSIZE

DYLIB_NAME = '/usr/lib/libobjc.A.dylib'
EXT_SYMBOL = '_OBJC_CLASS_$_NSObject'


def encode_chained_ptr_arm64(kind, value, next_off=0, ptr_size=8):
    """Encode one DYLD_CHAINED_PTR_ARM64 entry the way the linker writes it to disk."""
    if kind == 'rebase':
        #uint64_t target:36, high8:8, reserved:7, next:12, bind:1
        target = value & 0xFFFFFFFFF
        high8 = (value >> 36) & 0xFF
        raw = target | (high8 << 36) | ((next_off // ptr_size) << 51)
    elif kind == 'bind':
        #uint64_t ordinal:24, addend:8, reserved:19, next:12, bind:1
        raw = (value & 0xFFFFFF) | ((next_off // ptr_size) << 51) | (1 << 63)
    else:
        raw = 0
    return raw


def build_version_load_command():
    """LC_BUILD_VERSION, the command the original crash report tripped over."""
    return struct.pack('<IIIIII', LC_BUILD_VERSION, 24, 2, 0x000E0000, 0x000E0000, 0)


def uuid_load_command():
    return struct.pack('<II', LC_UUID, 24) + bytes(range(16))


def dylib_load_command():
    #LC_LOAD_DYLIB for one dylib, 8 byte aligned like the real linker emits it
    body = struct.pack('<IIII', 24, 2, 0x10000, 0x10000) + DYLIB_NAME.encode() + b'\x00'
    cmd = struct.pack('<II', LC_LOAD_DYLIB, 8 + len(body)) + body
    cmd += b'\x00' * ((8 - len(cmd) % 8) % 8)
    return struct.pack('<II', LC_LOAD_DYLIB, len(cmd)) + cmd[8:]


def section(name, seg, addr, size, offset, align=3, flags=S_REGULAR, reserved1=0, reserved2=0):
    return struct.pack('<16s16sQQIIIIIIII', name.encode(), seg.encode(), addr, size,
                       offset, align, 0, 0, flags, reserved1, reserved2, 0)


def segment(name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, sects):
    body = b''.join(sects)
    return struct.pack('<II16sQQQQIIII', LC_SEGMENT_64, 72 + len(body), name.encode(),
                       vmaddr, vmsize, fileoff, filesize, maxprot, initprot, len(sects), 0) + body


def objc_layout():
    '''Return (text_blob, data_blob, list of (seg_off_in_data, target_vmaddr)) fixups.'''
    text_vmaddr = BASE + TEXT_FILEOFF
    data_vmaddr = BASE + DATA_FILEOFF

    #__TEXT sections, laid out back to back starting at file offset 0x100
    methname = b'testMethod\x00'
    methtype = b'v16@0:8\x00'
    classname = b'MyClass\x00'
    cstring = b'hello\x00'

    off = 0x100
    methname_off = off
    off += len(methname)
    methtype_off = off
    off += len(methtype)
    classname_off = off
    off += len(classname)
    cstring_off = off
    off += len(cstring)

    text = bytearray(b'\x00' * 0x100)
    text += methname + methtype + classname + cstring
    text += b'\x00' * (TEXT_SIZE - len(text))
    assert len(text) == TEXT_SIZE

    #__DATA sections. The offsets of every piece are computed instead of hardcoded,
    #the dumper relies on __objc_data and __objc_const being contiguous.
    imp_addr = text_vmaddr + 0x200      #__text, only printed, never followed

    off = 0
    classrefs_off = off; off += 8            #__objc_classrefs[0], bound to _OBJC_CLASS_$_NSObject
    classlist_off = off; off += 8            #__objc_classlist[0], rebased to the class object
    nlclslist_off = off; off += 8            #__objc_nlclslist[0], left empty
    objc_data_off = off; off += 40           #_OBJC_CLASS_$_MyClass
    objc_meta_off = off; off += 40           #_OBJC_METACLASS_$_MyClass
    cls_ro_off = off; off += 72
    meta_ro_off = off; off += 72
    meth_list_off = off; off += 32
    ivar_list_off = off; off += 40
    #everything that holds a chained pointer has to be 8 byte aligned, so the two
    #byte sized blobs go last
    cfstring_off = off; off += 32
    selrefs_off = off; off += 8            #__objc_selrefs[0], rebased to __objc_methname
    ivar_off_field_off = off; off += 4     #__objc_ivar
    ivar_layout_off = off; off += 1
    pad = DATA_VMSIZE - off                                    #tail padding of the segment
    off += pad

    assert off == DATA_VMSIZE, 'DATA layout is 0x{:X} bytes, expected 0x{:X}'.format(off, DATA_VMSIZE)

    classrefs = struct.pack('<Q', 0)
    classlist = struct.pack('<Q', data_vmaddr + objc_data_off)
    nlclslist = struct.pack('<Q', data_vmaddr + objc_data_off)

    objc_data_cls = struct.pack('<QQQQQ',
                                data_vmaddr + objc_meta_off,      #isa (rebase)
                                0,                                #superclass (bind)
                                data_vmaddr + 0x150,              #cache (rebase, inside __DATA)
                                0,                                #vtable
                                data_vmaddr + cls_ro_off)         #class ro
    objc_data_meta = struct.pack('<QQQQQ',
                                 data_vmaddr + objc_meta_off,     #isa (self, rebase)
                                 0,                               #superclass (bind)
                                 data_vmaddr + 0x158,             #cache (rebase, inside __DATA)
                                 0,
                                 data_vmaddr + meta_ro_off)       #metaclass ro

    #class_ro is 4 uint32 (flags, instanceStart, instanceSize, reserved), 4 bytes of
    #padding and 7 pointers, 72 bytes in total. The uint32 header and the pointers are
    #packed separately because a mixed '<IIIIQQQQQQQ' format would make struct insert
    #padding of its own and emit the pointers at the wrong offsets.
    ivar_layout = struct.pack('<B', 0)
    cls_ro = struct.pack('<IIII', 0, 8, 16, 0) + struct.pack('<QQQQQQQ',
                                                             0,                          #ivar layout
                                                             text_vmaddr + classname_off,
                                                             data_vmaddr + meth_list_off,
                                                             0,                          #protocols
                                                             data_vmaddr + ivar_list_off,
                                                             0, 0)
    meta_ro = struct.pack('<IIII', 1, 8, 16, 0) + struct.pack('<QQQQQQQ',
                                                              0,                          #ivar layout
                                                              text_vmaddr + classname_off,
                                                              0, 0, 0, 0, 0)
    assert len(cls_ro) == 72 and len(meta_ro) == 72

    meth_list = struct.pack('<II', 24, 1) + struct.pack('<QQQ',
                                                        text_vmaddr + methname_off,
                                                        text_vmaddr + methtype_off,
                                                        imp_addr)

    ivar_off_field = struct.pack('<I', 8)
    #the dumper reads ivar names out of __TEXT,__objc_methname and types out of __objc_methtype
    ivar_list = struct.pack('<II', 32, 1) + struct.pack('<QQQLL',
                                                        data_vmaddr + ivar_off_field_off,
                                                        text_vmaddr + methname_off,
                                                        text_vmaddr + methtype_off,
                                                        3, 8)

    #the isa of a __CFString is an imported symbol, the string itself lives in __TEXT,__cstring
    cfstring = struct.pack('<QQQQ', 0, 0x7C8, text_vmaddr + cstring_off, len(cstring) - 1)
    selrefs = struct.pack('<Q', text_vmaddr + methname_off)

    data = bytearray()
    for blob in (classrefs, classlist, nlclslist, objc_data_cls, objc_data_meta, cls_ro,
                 meta_ro, meth_list, ivar_list, cfstring, selrefs, ivar_off_field,
                 ivar_layout, b'\x00' * pad):
        data += blob
    assert len(data) == DATA_VMSIZE

    #chained fixups / bind opcodes of the __DATA segment, keyed by segment offset
    fixups = [
        (classrefs_off, 'bind', None),                            #__objc_classrefs[0]
        (classlist_off, 'rebase', data_vmaddr + objc_data_off),
        (nlclslist_off, 'rebase', data_vmaddr + objc_data_off),
        (objc_data_off + 0, 'rebase', data_vmaddr + objc_meta_off),   #isa
        (objc_data_off + 8, 'bind', None),                            #superclass
        (objc_data_off + 16, 'rebase', data_vmaddr + 0x150),          #cache
        (objc_meta_off + 0, 'rebase', data_vmaddr + objc_meta_off),   #isa
        (objc_meta_off + 8, 'bind', None),                            #superclass
        (objc_meta_off + 16, 'rebase', data_vmaddr + 0x158),          #cache
        (cfstring_off, 'bind', None),                             #__cfstring isa
        (selrefs_off, 'rebase', text_vmaddr + methname_off),
    ]

    sections_text = [
        section('__objc_methname', '__TEXT', text_vmaddr + methname_off, len(methname), TEXT_FILEOFF + methname_off, align=0, flags=S_CSTRING_LITERALS),
        section('__objc_methtype', '__TEXT', text_vmaddr + methtype_off, len(methtype), TEXT_FILEOFF + methtype_off, align=0, flags=S_CSTRING_LITERALS),
        section('__objc_classname', '__TEXT', text_vmaddr + classname_off, len(classname), TEXT_FILEOFF + classname_off, align=0, flags=S_CSTRING_LITERALS),
        section('__cstring', '__TEXT', text_vmaddr + cstring_off, len(cstring), TEXT_FILEOFF + cstring_off, align=0, flags=S_CSTRING_LITERALS),
    ]
    sections_data = [
        section('__objc_classrefs', '__DATA', data_vmaddr + classrefs_off, 8, DATA_FILEOFF + classrefs_off),
        section('__objc_classlist', '__DATA', data_vmaddr + classlist_off, 8, DATA_FILEOFF + classlist_off, flags=S_MOD_INIT_FUNC_POINTERS),
        section('__objc_nlclslist', '__DATA', data_vmaddr + nlclslist_off, 8, DATA_FILEOFF + nlclslist_off, flags=S_MOD_INIT_FUNC_POINTERS),
        section('__objc_data', '__DATA', data_vmaddr + objc_data_off, 0x50, DATA_FILEOFF + objc_data_off),
        section('__objc_const', '__DATA', data_vmaddr + cls_ro_off, ivar_list_off + 40 - cls_ro_off, DATA_FILEOFF + cls_ro_off),
        section('__objc_ivar', '__DATA', data_vmaddr + ivar_off_field_off, 4, DATA_FILEOFF + ivar_off_field_off),
        section('__cfstring', '__DATA', data_vmaddr + cfstring_off, 32, DATA_FILEOFF + cfstring_off),
        section('__objc_selrefs', '__DATA', data_vmaddr + selrefs_off, 8, DATA_FILEOFF + selrefs_off),
    ]

    text_seg = segment('__TEXT', text_vmaddr, TEXT_SIZE, TEXT_FILEOFF, TEXT_SIZE, 5, 5, sections_text)
    data_seg = segment('__DATA', data_vmaddr, DATA_VMSIZE, DATA_FILEOFF, DATA_VMSIZE, 3, 3, sections_data)
    zeropage_seg = segment('__PAGEZERO', 0, BASE, 0, 0, 0, 0, [])
    return bytes(text), bytes(data), fixups, zeropage_seg, text_seg, data_seg, text_vmaddr, data_vmaddr


def build_chained_fixups_binary():
    text, data, fixups, zeropage_seg, text_seg, data_seg, text_vmaddr, data_vmaddr = objc_layout()

    #Every pointer of the __DATA blob is stored encoded, the vmaddr written by
    #objc_layout() is only the value the dumper has to get back after decoding.
    #All of them hang off a single chain that starts at the first fixup of the page and
    #is walked through the 'next' field, exactly like the linker emits it.
    fixups = sorted(fixups, key=lambda f: f[0])
    data = bytearray(data)
    for idx, (seg_off, kind, target) in enumerate(fixups):
        if idx + 1 < len(fixups):
            next_off = fixups[idx + 1][0] - seg_off
        else:
            next_off = 0                                 #end of the chain
        #DYLD_CHAINED_PTR_ARM64 stores the full unslid vmaddr of a rebase target and the
        #1 based index into the import table for a bind
        value = target if kind == 'rebase' else 1
        data[seg_off : seg_off + 8] = struct.pack('<Q', encode_chained_ptr_arm64(kind, value, next_off))
    data = bytes(data)
    page_starts = [fixups[0][0]]

    #linkedit payload: header + starts_in_image + per segment starts + imports + strings
    symbols = b'\x00' + EXT_SYMBOL.encode() + b'\x00'
    name_offset = 1
    imports = struct.pack('<I', (1 & 0xFF) | (0 << 8) | (name_offset << 9))

    starts_offset = struct.calcsize('<LLLLLLL')       #28, the header is not padded

    #one page, one chain: page_count is a number of pages, not a number of fixups
    page_starts = b''.join(struct.pack('<H', o) for o in page_starts)
    #NOTE: '<LHHQLL' packs without padding, the header really is 24 bytes
    assert struct.calcsize('<LHHQLL') == 24
    starts_data_hdr = struct.pack('<LHHQLL', 24 + len(page_starts), 0x1000, 3, data_vmaddr, 0, 1)
    starts_data = starts_data_hdr + page_starts
    starts_zero = struct.pack('<LHHQLL', 24, 0x1000, 3, 0, 0, 0)

    seg_count = 4
    #seg_info_offset is relative to the beginning of the chained fixups payload,
    #so it has to skip the header plus the seg_count/seg_info_offset array
    array_base = starts_offset + 4 + seg_count * 4     #absolute offset in the payload
    starts_in_image = struct.pack('<L', seg_count)
    starts_in_image += struct.pack('<L', array_base)                            #__PAGEZERO
    starts_in_image += struct.pack('<L', 0)                                     #__TEXT, no fixups
    starts_in_image += struct.pack('<L', array_base + len(starts_zero))         #__DATA
    starts_in_image += struct.pack('<L', 0)                                     #__LINKEDIT, no fixups
    starts_in_image += starts_zero + starts_data

    imports_offset = starts_offset + len(starts_in_image)
    symbols_offset = imports_offset + len(imports)
    chain_data = struct.pack('<LLLLLLL', 0, starts_offset, imports_offset, symbols_offset,
                             1, 1, 0)
    chain_data += starts_in_image + imports + symbols
    chain_data += b'\x00' * ((4 - len(chain_data) % 4) % 4)

    linkedit_seg = segment('__LINKEDIT', BASE + LINKEDIT_FILEOFF, len(chain_data),
                           LINKEDIT_FILEOFF, len(chain_data), 1, 1, [])

    dylib_cmd = dylib_load_command()

    chained_cmd = struct.pack('<IIII', LC_DYLD_CHAINED_FIXUPS, 24, LINKEDIT_FILEOFF, len(chain_data))
    dyld_info_cmd = struct.pack('<II' + 'L' * 10, LC_DYLD_INFO_ONLY, 48, *([0] * 10))

    load_cmds = (zeropage_seg + text_seg + data_seg + linkedit_seg + dylib_cmd +
                 build_version_load_command() + uuid_load_command() + dyld_info_cmd + chained_cmd)
    return assemble(text, data, chain_data, load_cmds)


def build_dyld_info_binary():
    text, data, fixups, zeropage_seg, text_seg, data_seg, text_vmaddr, data_vmaddr = objc_layout()

    #classic bind opcodes: bind the superclass field of both class and metaclass and __objc_classrefs[0]
    SET_DYLIB_ORDINAL_IMM = 0x10
    SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40
    SET_TYPE_IMM = 0x50
    SET_SEGMENT_AND_OFFSET_ULEB = 0x70
    DO_BIND = 0x90
    BIND_DONE = 0x00

    def uleb(value):
        out = bytearray()
        while True:
            byte = value & 0x7F
            value >>= 7
            if value:
                out.append(byte | 0x80)
            else:
                out.append(byte)
                break
        return bytes(out)

    bind = bytearray()
    bind.append(SET_DYLIB_ORDINAL_IMM | 1)
    bind.append(SET_SYMBOL_TRAILING_FLAGS_IMM | 0)
    bind += EXT_SYMBOL.encode() + b'\x00'
    bind.append(SET_TYPE_IMM | 1)
    for seg_off, kind, _target in fixups:
        if kind != 'bind':
            continue
        bind.append(SET_SEGMENT_AND_OFFSET_ULEB | 2)
        bind += uleb(seg_off)
        bind.append(DO_BIND)
    bind.append(BIND_DONE)
    bind = bytes(bind)

    linkedit_seg = segment('__LINKEDIT', BASE + LINKEDIT_FILEOFF, len(bind),
                           LINKEDIT_FILEOFF, len(bind), 1, 1, [])

    dylib_cmd = dylib_load_command()

    dyld_info_cmd = struct.pack('<II' + 'L' * 10, LC_DYLD_INFO_ONLY, 48,
                                0, 0, LINKEDIT_FILEOFF, len(bind), 0, 0, 0, 0, 0, 0)

    load_cmds = (zeropage_seg + text_seg + data_seg + linkedit_seg + dylib_cmd +
                 build_version_load_command() + uuid_load_command() + dyld_info_cmd)
    return assemble(text, data, bind, load_cmds)


def assemble(text, data, linkedit, load_cmds):
    #count load commands by walking them
    ncmds = 0
    pos = 0
    while pos < len(load_cmds):
        _, cmdsize = struct.unpack_from('<II', load_cmds, pos)
        ncmds += 1
        pos += cmdsize

    header = struct.pack('<IiiIIIII', MH_MAGIC_64, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL,
                         MH_EXECUTE, ncmds, len(load_cmds), 0, 0)

    #the mach header lives at the start of __TEXT, so pad the load commands up to TEXT_FILEOFF
    prefix = header + load_cmds
    if len(prefix) > TEXT_FILEOFF:
        raise ValueError('load commands do not fit before file offset 0x{:X}'.format(TEXT_FILEOFF))
    prefix += b'\x00' * (TEXT_FILEOFF - len(prefix))

    image = bytearray(prefix)
    image += text
    image += data
    image += linkedit
    return bytes(image)


def main():
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures')
    os.makedirs(out_dir, exist_ok=True)

    for name, builder in (('fixture_chained_fixups.bin', build_chained_fixups_binary),
                          ('fixture_dyld_info.bin', build_dyld_info_binary)):
        path = os.path.join(out_dir, name)
        with open(path, 'wb') as fd:
            fd.write(builder())
        print('wrote {:s} ({:d} bytes)'.format(path, os.path.getsize(path)))


if __name__ == '__main__':
    main()
