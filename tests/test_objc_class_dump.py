'''
Unit tests for objc_class_dump.

The tests run against two small synthetic arm64 Mach-O images built by
make_fixtures.py: one that carries its binding information in
LC_DYLD_CHAINED_FIXUPS (what a modern Xcode toolchain emits) and one that uses the
classic LC_DYLD_INFO_ONLY opcode stream. Both describe the same ObjC layout, so they
have to produce the same result.

Run with:

    python -m unittest discover -s tests -v
'''
import io
import os
import struct
import sys
import unittest
from contextlib import redirect_stdout

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import objc_class_dump as tool                                   # noqa: E402
from mach_header import (MACH_O_LOAD_COMMAND_TYPE,                # noqa: E402
                         load_command_name, load_command_type)

FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures')
CHAINED_FIXTURE = os.path.join(FIXTURE_DIR, 'fixture_chained_fixups.bin')
DYLD_INFO_FIXTURE = os.path.join(FIXTURE_DIR, 'fixture_dyld_info.bin')

FIXTURES = ('chained_fixups', 'dyld_info')


def build_fixtures():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import make_fixtures
    make_fixtures.main()


def load(fixture):
    with open(fixture, 'rb') as fd:
        out = io.StringIO()
        with redirect_stdout(out):
            analyzer = tool.MachOAnalyzer(fd)
    return analyzer, out.getvalue()


def dump_all(analyzer):
    out = io.StringIO()
    with redirect_stdout(out):
        analyzer.dump_objc_classlist()
        analyzer.dump_objc_nlclslist()
        analyzer.dump_section_objc_selrefs()
        analyzer.dump_section_objc_classrefs()
        analyzer.dump_section_objc_superrefs()
        analyzer.dump_section_objc_ivar()
        analyzer.dump_section_cfstring()
        analyzer.dump_import_table()
        analyzer.dump_virtual_section()
    return out.getvalue()


class FixtureTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for fixture in (CHAINED_FIXTURE, DYLD_INFO_FIXTURE):
            if not os.path.exists(fixture):
                build_fixtures()
                break


class TestLoadCommandTypes(FixtureTestCase):
    def test_modern_load_commands_are_known(self):
        #the values a modern toolchain puts into a Mach-O header
        expected = {
            0x2F: 'VERSION_MIN_TVOS',
            0x30: 'VERSION_MIN_WATCHOS',
            0x31: 'NOTE',
            0x32: 'BUILD_VERSION',
            0x80000033: 'DYLD_EXPORTS_TRIE',
            0x80000034: 'DYLD_CHAINED_FIXUPS',
            0x80000035: 'FILESET_ENTRY',
        }
        for value, name in expected.items():
            self.assertEqual(load_command_type(value).name, name,
                             'load command 0x{:X} should be {:s}'.format(value, name))

    def test_build_version_is_50(self):
        #the value from the original crash report
        self.assertEqual(MACH_O_LOAD_COMMAND_TYPE.BUILD_VERSION.value, 50)

    def test_unknown_load_command_is_tolerated(self):
        self.assertIsNone(load_command_type(0x1234))
        self.assertEqual(load_command_name(0x1234), 'LC_UNKNOWN(0x1234)')

    def test_dyld_info_only_is_an_alias_of_dyld_info(self):
        self.assertEqual(MACH_O_LOAD_COMMAND_TYPE.DYLD_INFO_ONLY.value,
                         MACH_O_LOAD_COMMAND_TYPE.DYLD_INFO.value)


class TestAnalyzer(unittest.TestCase):
    '''Both fixtures describe the same image, so they are checked with the same tests.'''

    def _check(self, fixture, chained):
        analyzer, log = load(fixture)

        self.assertNotIn('Traceback', log)
        segments = [s.name for s in analyzer._MachOAnalyzer__segments]
        self.assertEqual(segments, ['__PAGEZERO', '__TEXT', '__DATA', '__LINKEDIT'])

        #import table
        dylibs = analyzer._MachOAnalyzer__dylibs
        self.assertEqual(len(dylibs), 1)
        self.assertEqual(dylibs[0].name, '/usr/lib/libobjc.A.dylib')
        self.assertEqual(dylibs[0].symbols, ['_OBJC_CLASS_$_NSObject'])

        #the import has to end up in the virtual section so that bound pointers resolve
        vsec = analyzer._MachOAnalyzer__virtual_section
        self.assertEqual([v.symbol for v in vsec], ['_OBJC_CLASS_$_NSObject'])
        self.assertEqual(analyzer.get_virtual_map_addr('_OBJC_CLASS_$_NSObject'), vsec[0].addr)
        self.assertEqual(analyzer.get_virtual_map_symbol(vsec[0].addr), '_OBJC_CLASS_$_NSObject')

        #chained fixups must have been found only in the chained fixture
        self.assertEqual(analyzer._MachOAnalyzer__chained_fixups is not None, chained)

        #class hierarchy
        classes = analyzer._MachOAnalyzer__objc_classlist
        self.assertEqual([c.name for c in classes], ['_OBJC_CLASS_$_MyClass'])
        my_class = classes[0]
        self.assertEqual(my_class.isa_name, '_OBJC_METACLASS_$_MyClass')
        self.assertEqual(my_class.superclass_name, '_OBJC_CLASS_$_NSObject')
        self.assertIsNone(my_class.superclass, 'an imported superclass must not be walked')
        self.assertEqual(my_class.class_data.cls_name, 'MyClass')
        self.assertEqual([(m.name, m.type, m.imp) for m in my_class.class_data.methods],
                         [('testMethod', 'v16@0:8', '0x100001200')])
        self.assertEqual([(i.name, i.type, i.offset, i.size) for i in my_class.class_data.ivars],
                         [('testMethod', 'v16@0:8', 8, 8)])

        #the metaclass is reachable through the decoded isa pointer
        meta = my_class.isa
        self.assertEqual(meta.name, '_OBJC_METACLASS_$_MyClass')
        self.assertEqual(meta.class_data.flags, 1)
        self.assertEqual(meta.superclass_name, '_OBJC_CLASS_$_NSObject')

        #non lazy class list
        nlclasses = analyzer._MachOAnalyzer__objc_nlclslist
        self.assertEqual([c.name for c in nlclasses], ['_OBJC_CLASS_$_MyClass'])

        #dumped sections
        dump = dump_all(analyzer)
        self.assertIn("__objc_methname('testMethod')", dump)          #__objc_selrefs
        self.assertIn('0x100002000: _OBJC_CLASS_$_NSObject', dump)    #__objc_classrefs
        self.assertIn("__CFString<_OBJC_CLASS_$_NSObject, 0x7C8, 'hello', 5>", dump)
        self.assertIn('section __DATA,__objc_superrefs not found', dump)
        self.assertIn('_OBJC_CLASS_$_NSObject', dump)

        return analyzer

    def test_chained_fixups_fixture(self):
        self._check(CHAINED_FIXTURE, chained=True)

    def test_dyld_info_fixture(self):
        self._check(DYLD_INFO_FIXTURE, chained=False)

    def test_both_fixtures_agree(self):
        chained, _ = load(CHAINED_FIXTURE)
        legacy, _ = load(DYLD_INFO_FIXTURE)

        #the virtual section is a synthetic range appended after __LINKEDIT, so its
        #addresses legitimately differ between the two images
        def without_virtual_section(dump):
            return [line for line in dump.splitlines()
                    if not line.startswith('0x') or ':_OBJC' not in line]

        self.assertEqual(without_virtual_section(dump_all(chained)),
                         without_virtual_section(dump_all(legacy)))


class TestSectionLookup(unittest.TestCase):
    def test_section_by_addr_uses_segment_offsets(self):
        analyzer, _ = load(CHAINED_FIXTURE)
        segment = analyzer.get_segment(2)
        self.assertEqual(segment.name, '__DATA')

        for name, probe in (('__objc_classrefs', 0x0), ('__objc_data', 0x18),
                            ('__objc_const', 0x68), ('__cfstring', 0x140),
                            ('__objc_selrefs', 0x160)):
            section = analyzer.get_section_by_addr(2, probe)
            self.assertIsNotNone(section, 'no section for segment offset 0x{:X}'.format(probe))
            self.assertEqual(section.name, name)

        #outside of every section
        self.assertIsNone(analyzer.get_section_by_addr(2, 0x4000))
        self.assertIsNone(analyzer.get_section_by_addr(99, 0))

        section, position = analyzer.get_section_position(2, 0x144)
        self.assertEqual(section.name, '__cfstring')
        self.assertEqual(position, 4)


class TestRobustness(unittest.TestCase):
    def test_no_imports_does_not_crash(self):
        analyzer, _ = load(CHAINED_FIXTURE)
        analyzer._MachOAnalyzer__virtual_section = []
        self.assertFalse(analyzer.is_virtual_section_addr(0x100000000))
        self.assertIsNone(analyzer.get_virtual_map_symbol(0x100000000))

    def test_unmapped_virtual_address_is_printed(self):
        analyzer, _ = load(CHAINED_FIXTURE)
        analyzer._MachOAnalyzer__virtual_section = []
        out = io.StringIO()
        with redirect_stdout(out):
            analyzer.dump_section_cfstring()
        self.assertIn('__CFString<0x', out.getvalue())

    def _analyze_corrupted(self, mutate):
        with open(CHAINED_FIXTURE, 'rb') as fd:
            data = bytearray(fd.read())
        mutate(data)
        path = os.path.join(FIXTURE_DIR, 'tmp_corrupted.bin')
        try:
            with open(path, 'wb') as fd:
                fd.write(bytes(data))
            with open(path, 'rb') as fd:
                out = io.StringIO()
                with redirect_stdout(out):
                    tool.MachOAnalyzer(fd)
            return out.getvalue()
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_truncated_load_command_region(self):
        #sizeofcmds lives at offset 20 of a 64 bit mach_header, claim it only holds one command
        out = self._analyze_corrupted(lambda data: struct.pack_into('<I', data, 20, 8))
        self.assertIn('outside of the load command region', out)

    def test_unknown_load_command_is_skipped(self):
        #replace LC_UUID by a load command this tool does not know, keeping its size so
        #that every other load command stays where it is. This is the situation the
        #original "50 is not a valid MACH_O_LOAD_COMMAND_TYPE" crash report described.
        def to_unknown(data):
            ncmds, sizeofcmds = struct.unpack_from('<II', data, 16)
            pos = 32
            for _ in range(ncmds):
                cmd, cmdsize = struct.unpack_from('<II', data, pos)
                if cmd == 0x1B:                                   #LC_UUID
                    struct.pack_into('<I', data, pos, 0x7FFFFFFF)
                    return
                pos += cmdsize
            raise AssertionError('LC_UUID not found in the fixture')

        out = self._analyze_corrupted(to_unknown)
        self.assertNotIn('Traceback', out)
        self.assertNotIn('is not a valid MACH_O_LOAD_COMMAND_TYPE', out)

        #the rest of the image still has to be analyzed
        path = os.path.join(FIXTURE_DIR, 'tmp_corrupted.bin')
        try:
            with open(CHAINED_FIXTURE, 'rb') as fd:
                data = bytearray(fd.read())
            to_unknown(data)
            with open(path, 'wb') as fd:
                fd.write(bytes(data))
            with open(path, 'rb') as fd:
                out = io.StringIO()
                with redirect_stdout(out):
                    analyzer = tool.MachOAnalyzer(fd)
            self.assertEqual([c.name for c in analyzer._MachOAnalyzer__objc_classlist],
                             ['_OBJC_CLASS_$_MyClass'])
            self.assertEqual(analyzer._MachOAnalyzer__dylibs[0].symbols, ['_OBJC_CLASS_$_NSObject'])
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_invalid_load_command_size(self):
        #cmdsize of the first load command, right behind ncmds/sizeofcmds
        out = self._analyze_corrupted(lambda data: struct.pack_into('<I', data, 36, 4))
        self.assertIn('invalid load command size', out)


if __name__ == '__main__':
    unittest.main(verbosity=2)
