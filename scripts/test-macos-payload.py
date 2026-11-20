"""Synthetic metadata fixtures; no executable code is run."""
import importlib.util
import struct
import unittest
import tempfile
import zlib
from pathlib import Path
s = importlib.util.spec_from_file_location('payload', Path(__file__).with_name('check-macos-payload.py'))
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)

def thin(cpu=0x100000c, minimum=0x000d0500, platform=1, legacy=False, endian='<'):
    command = struct.pack(endian+'IIII', 0x24,16,minimum,0) if legacy else struct.pack(endian+'IIIIII',0x32,24,platform,minimum,0,0)
    return struct.pack(endian+'IIIIIIII',0xfeedfacf,cpu,0,2,1,len(command),0,0)+command

def fat(a,b,wide=False):
    size=32 if wide else 20; off=8+2*size
    return struct.pack('>II',0xcafebabf if wide else 0xcafebabe,2)+struct.pack('>IIQQII' if wide else '>IIIII',0x1000007,0,off,len(a),0,*([0] if wide else []))+struct.pack('>IIQQII' if wide else '>IIIII',0x100000c,0,off+len(a),len(b),0,*([0] if wide else []))+a+b

class PayloadTests(unittest.TestCase):
    def test_bounded_archive_members(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'payload';data=b'native bytes';packed=zlib.compress(data)
            p.write_bytes(b'prefix'+packed)
            self.assertEqual(m.extract_member(p,6,(0,len(packed),len(data),1,'b'),64),data)
            p.write_bytes(data)
            self.assertEqual(m.extract_member(p,0,(0,len(data),len(data),0,'b'),64),data)
    def test_archive_expansion_size_cannot_lie(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'payload';packed=zlib.compress(b'A'*10000);p.write_bytes(packed)
            with self.assertRaises(ValueError): m.extract_member(p,0,(0,len(packed),1,1,'b'),64)
            with self.assertRaises(ValueError): m.extract_member(p,0,(0,len(packed),10000,1,'b'),64)
    def test_archive_truncation_trailing_and_bounds(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'payload';packed=zlib.compress(b'abc')
            for body,expected in [(packed[:-1],3),(packed+b'junk',3),(packed,4),(b'abc',2)]:
                p.write_bytes(body)
                with self.assertRaises(ValueError): m.extract_member(p,0,(0,len(body),expected,1 if body!=b'abc' else 0,'b'),64)
            p.write_bytes(packed)
            for entry in [(-1,len(packed),3,1,'b'),(0,len(packed)+1,3,1,'b'),(0,len(packed),3,2,'b')]:
                with self.assertRaises(ValueError): m.extract_member(p,0,entry,64)
    def test_thin_and_endian(self):
        for endian in '<>': self.assertEqual(m.component(thin(endian=endian),'x','arm64')['minimum'],'13.5.0')
    def test_legacy(self): self.assertEqual(m.slices(thin(legacy=True))[0]['minimum'],'13.5.0')
    def test_fat_target_selection(self):
        for wide in (False,True):
            data=fat(thin(cpu=0x1000007,minimum=0x000f0000),thin(),wide)
            self.assertEqual(m.component(data,'x','arm64')['minimum'],'13.5.0')
            self.assertEqual(m.component(data,'x','x86_64')['minimum'],'15.0.0')
    def test_wrong_arch_and_platform(self):
        for data in (thin(cpu=0x1000007),thin(platform=2)):
            with self.assertRaises(ValueError): m.component(data,'x','arm64')
    def test_missing_and_malformed(self):
        for data in (b'',thin()[:20],thin()[:-1],thin(minimum=0),struct.pack('<IIIIIIII',0xfeedfacf,0x100000c,0,2,0,0,0,0)):
            with self.assertRaises(ValueError): m.slices(data)
        for value in (None,'13','13.5x',''):
            with self.assertRaises(ValueError): m.version(value)
    def test_declared_floor(self):
        required=m.version(m.component(thin(),'x','arm64')['minimum'])
        self.assertLess(m.version('11.0'),required)
        self.assertGreaterEqual(m.version('13.5'),required)
        self.assertGreaterEqual(m.version('14.0'),required)
    def test_fat_bounds(self):
        with self.assertRaises(ValueError): m.slices(fat(thin(cpu=0x1000007),thin())[:-1])
    def test_nested_bundle_floor_is_bounded_by_its_code_and_the_app(self):
        import plistlib
        nested='Contents/Resources/resources/v2/bin/OMD Sign-In.app'
        def rows(minimum):
            return [m.component(thin(),'Contents/MacOS/app','arm64'),m.component(thin(minimum=minimum),nested+'/Contents/MacOS/omd-signin','arm64')]
        with tempfile.TemporaryDirectory() as folder:
            app=Path(folder)/'Fixture.app';info=app/nested/'Contents/Info.plist';info.parent.mkdir(parents=True)
            def declare(**values): info.write_bytes(plistlib.dumps({'CFBundleExecutable':'omd-signin','LSMinimumSystemVersion':'11.0',**values}))
            declare()
            self.assertEqual(m.nested_bundles(app,rows(0x000b0000),'13.5'),[{'path':nested,'declared':'11.0','required':'11.0.0','pass':True}])
            self.assertFalse(m.nested_bundles(app,rows(0x000c0000),'13.5')[0]['pass'])
            declare(LSMinimumSystemVersion='14.0')
            self.assertFalse(m.nested_bundles(app,rows(0x000b0000),'13.5')[0]['pass'])
            for values in ({'LSMinimumSystemVersion':'eleven'},{'LSMinimumSystemVersionByArchitecture':{'arm64':'11.0'}},{'CFBundleExecutable':'other'}):
                declare(**values)
                with self.assertRaises(ValueError): m.nested_bundles(app,rows(0x000b0000),'13.5')
            info.unlink()
            self.assertEqual(m.nested_bundles(app,rows(0x000b0000),'13.5'),[])

if __name__=='__main__': unittest.main()
