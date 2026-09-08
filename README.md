# objc_class_dump



A object-c class dumper written in Python

The famous object-c class-dump (https://github.com/nygard/class-dump) is not very handy when doing some assembler language level IOS application ananlysis.

So I developed an objc_class_dump with Python from scrath.

This tool not only dumps the hierarchy of all object-c classes but also dumps raw information of some other sections.

It was developed with Python 3.7+ and tested with Mach-O file with arm and aarch64 architecture.

How it works:

1. Detects Fat Mach-O header magic

2. Detects Mach-O Header magic

3. Loads all sections into memory

4. Build an import table based on LC_LOAD_DYLIB and the binding information

5. Build an virtual section for all imported symbols

6. Bind to imported symbols based on the binding information

7. Build hierarchy of object-c class list and non-lazy class list

How to use:

    $ python objc_class_dump.py [options] <mach-o-file>

## Binding information

Two encodings are supported, the tool picks whichever the image carries:

* `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY`, the classic opcode stream
* `LC_DYLD_CHAINED_FIXUPS`, what Xcode 12+ emits for iOS 13.4+ / macOS 11+ targets

With chained fixups every pointer in a fixup page is stored *encoded*, so the tool
decodes each chain (`DYLD_CHAINED_PTR_ARM64`, `ARM64E`, `ARM64E_USERLAND`,
`ARM64E_USERLAND24`, `X86_64_CACHEABLE`, `ARM64_32` and the kernel/firmware variants),
reads the import table out of the linkedit payload and writes the resolved vmaddr back
into the in-memory copy of the section. A rebase entry of a user space format holds the
absolute unslid vmaddr, only the kernel/firmware formats store an offset relative to the
preferred address of the segment.

Load commands the tool does not know are skipped by using their `cmdsize`, so a binary
built with a newer toolchain (`LC_BUILD_VERSION`, `LC_DYLD_EXPORTS_TRIE`, ...) is still
analyzed instead of aborting with `ValueError: N is not a valid MACH_O_LOAD_COMMAND_TYPE`.

Known limitations:

> - the addend of a bind is not applied, the virtual section data structure would have to carry it
> - `LC_DYLD_CHAINED_FIXUPS` payloads with zlib compressed symbol strings are not decoded
> - ivar layouts are looked up in `__TEXT,__objc_classname` only
> - `__objc_protolist` is not dumped yet

## Tests

The test suite runs against two small synthetic arm64 Mach-O images that describe the
same ObjC layout, one using chained fixups and one using `LC_DYLD_INFO_ONLY`, so both
binding paths have to produce the same result:

    $ python -m unittest discover -s tests -v

`tests/make_fixtures.py` regenerates them into `tests/fixtures/`.

# TODO:
---
> - dump __objc_protolist
> - Documentation

