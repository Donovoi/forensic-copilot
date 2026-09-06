"""Synthetic tests: fake native tools, explicit synthetic preservation, no evidence."""
from pathlib import Path
import contextlib
import hashlib
import importlib.util
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('carve_supervisor_under_test', HERE / 'supervise_photorec.py')
s = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = s
spec.loader.exec_module(s)
GATE = HERE / 'collect_image_inventory.py'
gate = s.load_gate(GATE)

FAKE = r'''
from pathlib import Path
import html,json,os,sys,time
base=Path(__file__).resolve().parent
settings=json.loads((base/'fake-settings.json').read_text())
mode=settings.get('mode','ok')
name=sys.argv[1]
with (base/'invocations.jsonl').open('a') as f:f.write(json.dumps(sys.argv)+'\n')
if name=='fsstat':
 print('File System Type: NTFS\nSector Size: 512\nCluster Size: 512\nTotal Cluster Range: 0 - 127\nTotal Sector Range: 0 - 127')
elif name=='istat':
 print('Allocated File\nName: $Bitmap\nType: $DATA (128-9)   Name: N/A   Non-Resident   size: 16  init_size: 16')
elif name=='icat':
 assert sys.argv[-1]=='6-128-9'
 b=bytearray(16);b[6]=1
 if mode=='short_bitmap':b=b[:-1]
 if mode=='oversize_bitmap':b.extend(bytes(100))
 sys.stdout.buffer.write(b)
elif name=='photorec':
 args=sys.argv
 image=Path(args[args.index('/cmd')+1])
 prefix=Path(args[args.index('/d')+1])
 log=Path(args[args.index('/logname')+1])
 d=Path(str(prefix)+'.1');d.mkdir()
 payload=image.read_bytes()[(63+32)*512:(63+32)*512+1200]
 path=d/'f0000032.bin'
 if mode=='sleep':time.sleep(20)
 if mode=='write_image':image.write_bytes(b'damaged')
 if mode=='oversize':payload=bytes(2*1024*1024)
 path.write_bytes(payload)
 if mode=='hardlink':path.unlink();os.link(base/'outside.bin',path)
 if mode=='extra':(d/'f0000090.bin').write_bytes(b'extra')
 if mode=='root_extra':(prefix.parent/'unexplained.bin').write_bytes(b'extra')
 if mode=='thumbnail':(d/'t0000032.jpg').write_bytes(b'fake-thumbnail')
 if mode=='nonjpeg_thumbnail':(d/'t0000032.exe').write_bytes(b'not-a-thumbnail')
 if mode=='missing':path.unlink()
 if mode=='stderr':sys.stderr.write('fake failure\n')
 total=2 if mode=='extra' else 1
 trace='' if mode=='no_trace' else 'ntfs_remove_used_space\n'
 log.write_text(trace+('Error: could not read bitmap\n' if mode=='error_log' else '')+
                f'Total: {total} file found\nPhotoRec exited normally.\n')
 if mode=='big_log':log.write_bytes(b'X'*50000)
 source=str(image) if mode!='wrong_source' else str(base/'unrelated.raw')
 start=(63+32)*512 if mode!='allocated' else (63+48)*512
 if mode=='outside':start=0
 if mode=='beyond':start=image.stat().st_size
 fname='f0000032.bin' if mode!='path_escape' else str(base/'outside.bin')
 size=len(payload) if mode!='wrong_size' else len(payload)+1
 record=f"<fileobject><filename>{html.escape(fname)}</filename><filesize>{size}</filesize><byte_runs><byte_run offset='0' img_offset='{start}' len='1536'/></byte_runs></fileobject>"
 if mode=='duplicate':record+=record
 if mode=='metadata':record+="<fileobject><filename>f0000060.mft</filename><filesize>512</filesize><byte_runs><byte_run offset='0' img_offset='62976' len='512'/></byte_runs></fileobject>"
 report="<?xml version='1.0' encoding='UTF-8'?><dfxml><creator><package>PhotoRec</package><version>7.2</version></creator>"
 report+=f"<source><image_filename>{html.escape(source)}</image_filename><image_size>{image.stat().st_size}</image_size><sectorsize>512</sectorsize><volume><byte_runs><byte_run offset='0' img_offset='32256' len='66048'/></byte_runs><block_size>512</block_size></volume></source>"+record+'</dfxml>'
 if mode in ('foreign_fileobject','wrapped_fileobject','misplaced_fileobject','misplaced_extent'):
  injected="<fileobject><filename>f0000048.bin</filename><filesize>512</filesize><byte_runs><byte_run offset='0' img_offset='56832' len='512'/></byte_runs></fileobject>"
  if mode=='foreign_fileobject':injected=injected.replace('<fileobject>',"<fileobject xmlns='urn:foreign'>")
  if mode=='wrapped_fileobject':injected='<unrecognized>'+injected+'</unrecognized>'
  if mode=='misplaced_fileobject':injected='<configuration>'+injected+'</configuration>'
  if mode=='misplaced_extent':injected="<configuration><byte_run offset='0' img_offset='56832' len='512'/></configuration>"
  report=report.replace('</dfxml>',injected+'</dfxml>')
 if mode=='malformed':report=report[:-8]
 if mode=='entity':report=report.replace('<dfxml>',"<!DOCTYPE dfxml [<!ENTITY x SYSTEM 'file:///outside'>]><dfxml>")
 if mode=='utf16':(d/'report.xml').write_bytes(report.replace('UTF-8','UTF-16').encode('utf-16'))
 else:(d/'report.xml').write_text(report,encoding='utf-8')
 if mode=='exit_failure':sys.exit(3)
'''


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='photorec-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.original = self.root / 'original.raw'
        self.image = self.root / 'working.raw'
        blob = bytearray(512 * (63 + 129))
        blob[510:512] = b'\x55\xaa'
        blob[450] = 7
        struct.pack_into('<II', blob, 454, 63, 129)
        start = 63 * 512
        blob[start+3:start+11] = b'NTFS    '
        struct.pack_into('<H', blob, start + 11, 512)
        blob[start + 13] = 1
        struct.pack_into('<Q', blob, start + 40, 128)
        blob[start+510:start+512] = b'\x55\xaa'
        self.payload = b'A' * 400 + bytes(500) + b'Z' * 300
        blob[(63+32)*512:(63+32)*512+len(self.payload)] = self.payload
        self.original.write_bytes(blob)
        self.image.write_bytes(blob)
        self.before = s.sha(self.image)
        self.preserve = self.root / 'preserve'
        self.preserve.mkdir()
        self.exit_path = self.root / 'preserve-exit.txt'
        self.exit_path.write_text('0')
        source_meta = gate.metadata(self.original.stat())
        dest_meta = gate.metadata(self.image.stat())
        now = gate.utc_now()
        manifest = {'schema_version': 1, 'source': str(self.original), 'source_metadata': source_meta,
            'destination': str(self.image), 'state_dir': str(self.preserve),
            'destination_identity': {key: dest_meta[key] for key in ('device','inode')},
            'final_destination_metadata': dest_meta, 'last_verified_sha256': self.before, 'last_verified_utc': now}
        status = {'schema_version': 1, 'phase': 'complete', 'verified': True, 'destination': str(self.image),
            'state_dir': str(self.preserve), 'source_stream_sha256': self.before, 'destination_sha256': self.before,
            'completed_utc': now, 'destination_metadata': dest_meta,
            **{key: len(blob) for key in ('source_size','copied_bytes','checkpoint_bytes','destination_verified_bytes')}}
        (self.preserve/'manifest.json').write_text(json.dumps(manifest))
        (self.preserve/'status.json').write_text(json.dumps(status))
        self.tools = self.root / 'tools'
        self.tools.mkdir()
        self.fake = self.root / 'fake.py'
        self.fake.write_text(FAKE)
        (self.root/'outside.bin').write_bytes(b'outside untouched')
        self.c = s.Config(image=self.image, preservation_state=self.preserve, preservation_exit_code=self.exit_path,
            gate_module=GATE, approved_tools=HERE/'photorec-7.2-tools.json', photorec_dir=self.tools, tsk_bin=self.tools,
            state_dir=self.root/'state', output_dir=self.root/'outputs', partition_number=1, partition_offset=63,
            partition_length=129, sector_size=512, max_output_bytes=10*s.MIB, max_files=100,
            max_log_bytes=s.MIB, max_seconds=20, poll_seconds=.02, reserve_bytes=0, cushion_bytes=0)

    @contextlib.contextmanager
    def fake_tools(self, c, g):
        executable = str(Path(sys.executable).resolve())
        yield {name: [executable, str(self.fake), name] for name in ('fsstat','istat','icat','photorec')} | {'records': []}

    def run_mode(self, mode='ok'):
        (self.root/'fake-settings.json').write_text(json.dumps({'mode':mode}))
        with mock.patch.object(s, 'locked_tools', self.fake_tools):
            result = s.supervise(self.c)
        self.assertEqual(s.sha(self.image), self.before)
        return result

    def status(self):
        return json.loads((self.c.state_dir/'status.json').read_text())

    def test_valid_fidelity_and_full_attr_id(self):
        self.assertEqual(self.run_mode(), 0)
        path = self.c.output_dir/'recup.1/f0000032.bin'
        self.assertEqual(path.read_bytes(), self.payload)
        row = json.loads((self.c.state_dir/'output-manifest.jsonl').read_text())
        self.assertEqual(row['sha256'], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(row['physical_padding_bytes'], 336)
        self.assertTrue(self.status()['reported_allocation_extents_verified'])

    def test_pending_gate_no_image_or_state(self):
        self.exit_path.unlink()
        self.image.unlink()
        with self.assertRaisesRegex(s.CarveError, 'Preservation incomplete'):
            self.run_mode()
        self.assertFalse(self.c.state_dir.exists())
        self.assertFalse((self.root/'invocations.jsonl').exists())

    def test_numbered_image_rejected(self):
        self.c.image = self.root/'image.001'
        with self.assertRaisesRegex(s.CarveError, 'Numbered'):
            s.supervise(self.c)

    def test_existing_output_untouched(self):
        self.c.output_dir.mkdir()
        (self.c.output_dir/'sentinel').write_bytes(b'safe')
        with self.assertRaises(s.CarveError):
            self.run_mode()
        self.assertEqual((self.c.output_dir/'sentinel').read_bytes(), b'safe')

    def test_state_output_overlap(self):
        self.c.output_dir = self.c.state_dir/'out'
        with self.assertRaises(s.CarveError):
            self.run_mode()

    def test_geometry_refused_before_tools(self):
        self.c.partition_length = 128
        self.assertEqual(self.run_mode(), 1)
        self.assertFalse((self.root/'invocations.jsonl').exists())

    def test_bad_sector_refused(self):
        self.c.sector_size = 4096
        with self.assertRaises(s.CarveError):
            self.run_mode()

    def test_bad_gate_hash(self):
        bad = self.root/'gate.py'
        bad.write_text('raise RuntimeError("must never execute")')
        self.c.gate_module = bad
        with self.assertRaisesRegex(s.CarveError, 'hash mismatch'):
            s.supervise(self.c)

    def test_tool_manifest_mismatch(self):
        bad = self.root/'bad-tools.json'
        bad.write_text('{}')
        self.c.approved_tools = bad
        self.assertEqual(s.supervise(self.c), 1)
        self.assertFalse((self.root/'invocations.jsonl').exists())

    def test_failure_modes_refuse_completion(self):
        # Individual subprocess integration controls; separate fixture ownership.
        modes = ['short_bitmap','oversize_bitmap','no_trace','error_log','wrong_source','allocated','outside','beyond',
                 'path_escape','duplicate','wrong_size','missing','extra','root_extra','entity','utf16','malformed',
                 'stderr','exit_failure','hardlink']
        for mode in modes:
            with self.subTest(mode=mode):
                case = SupervisorTests()
                case.setUp()
                try:
                    code = case.run_mode(mode)
                    self.assertNotEqual(code, 0)
                    self.assertFalse(case.status()['scan_completed'])
                    invoked = (case.root/'invocations.jsonl').read_text()
                    self.assertIn('icat', invoked)
                    if mode not in ('short_bitmap','oversize_bitmap'):
                        self.assertIn('photorec', invoked)
                finally:
                    case.doCleanups()

    def test_metadata_only_record(self):
        self.assertEqual(self.run_mode('metadata'), 0)
        self.assertEqual(self.status()['report_only_candidates'], 1)

    def test_thumbnail_unmapped_is_explicit(self):
        self.assertEqual(self.run_mode('thumbnail'), 0)
        self.assertEqual(self.status()['unmapped_thumbnails'], 1)
        rows = [json.loads(line) for line in (self.c.state_dir/'output-manifest.jsonl').read_text().splitlines()]
        self.assertEqual(rows[-1]['allocation_validation'], 'unverified_thumbnail_parent')

    def test_report_structure_and_thumbnail_regressions(self):
        for mode in ('foreign_fileobject','wrapped_fileobject','misplaced_fileobject','misplaced_extent','nonjpeg_thumbnail'):
            with self.subTest(mode=mode):
                case = SupervisorTests()
                case.setUp()
                try:
                    self.assertEqual(case.run_mode(mode), 1)
                    self.assertFalse(case.status()['scan_completed'])
                    self.assertTrue((case.c.output_dir/'recup.1/report.xml').exists())
                    self.assertNotIn('reported_allocation_extents_verified', case.status())
                finally:
                    case.doCleanups()

    def make_monitor(self):
        self.c.state_dir.mkdir()
        self.c.output_dir.mkdir()
        nested = self.c.output_dir/'recup.1'/'nested'
        nested.mkdir(parents=True)
        return s.Recorder(self.c, gate), nested

    def test_monitor_nested_hardlink_refused(self):
        rec, nested = self.make_monitor()
        os.link(self.root/'outside.bin', nested/'f0000001.bin')
        with self.assertRaisesRegex(s.CarveError, 'hardlinked'):
            rec.check(force_status=True)
        self.assertEqual((self.root/'outside.bin').read_bytes(), b'outside untouched')

    def test_monitor_nested_file_symlink_refused(self):
        rec, nested = self.make_monitor()
        try:
            os.symlink(self.root/'outside.bin', nested/'f0000001.bin')
        except OSError as error:
            self.skipTest(f'File symlink privilege unavailable: {error}')
        with self.assertRaisesRegex(s.CarveError, 'Symlink/reparse'):
            rec.check(force_status=True)

    @unittest.skipUnless(os.name == 'nt', 'Windows junction regression')
    def test_monitor_nested_junction_refused(self):
        rec, nested = self.make_monitor()
        target = self.root/'external-directory'
        target.mkdir()
        (target/'sentinel').write_bytes(b'untouched')
        link = nested/'junction'
        p = subprocess.run(['cmd.exe','/d','/c','mklink','/J',str(link),str(target)],
                           capture_output=True, timeout=10, creationflags=0x08000000)
        self.assertEqual(p.returncode, 0, p.stderr.decode(errors='replace'))
        with self.assertRaisesRegex(s.CarveError, 'Symlink/reparse'):
            rec.check(force_status=True)
        self.assertEqual((target/'sentinel').read_bytes(), b'untouched')

    @unittest.skipUnless(os.name == 'nt', 'Windows root junction regression')
    def test_monitor_replaced_output_root_junction_refused(self):
        self.c.state_dir.mkdir()
        target = self.root/'external-directory'
        target.mkdir()
        p = subprocess.run(['cmd.exe','/d','/c','mklink','/J',str(self.c.output_dir),str(target)],
                           capture_output=True, timeout=10, creationflags=0x08000000)
        self.assertEqual(p.returncode, 0, p.stderr.decode(errors='replace'))
        rec = s.Recorder(self.c, gate)
        with self.assertRaisesRegex(s.CarveError, 'Symlink/reparse'):
            rec.check(force_status=True)

    def test_output_stop_retains_partial(self):
        self.c.max_output_bytes = s.MIB
        self.assertEqual(self.run_mode('oversize'), 2)
        self.assertEqual(self.status()['phase'], 'incomplete')
        self.assertTrue((self.c.output_dir/'recup.1/f0000032.bin').exists())
        self.assertTrue((self.c.state_dir/'retained-outputs.partial.jsonl').exists())

    def test_file_count_stop(self):
        self.c.max_files = 1
        self.assertEqual(self.run_mode('extra'), 2)

    def test_runtime_stop_kills_process(self):
        self.c.max_seconds = .4
        before = time.monotonic()
        self.assertEqual(self.run_mode('sleep'), 2)
        self.assertLess(time.monotonic()-before, 4)

    def test_reserve_stop_before_native_launch(self):
        usage = shutil._ntuple_diskusage(100,100,0)
        with mock.patch.object(s.shutil, 'disk_usage', return_value=usage):
            self.assertEqual(self.run_mode(), 2)
        self.assertFalse((self.root/'invocations.jsonl').exists())

    def test_log_stop(self):
        self.c.max_log_bytes = 20000
        self.assertEqual(self.run_mode('big_log'), 2)

    @unittest.skipUnless(os.name == 'nt', 'Windows mandatory locking')
    def test_image_write_is_denied(self):
        self.assertEqual(self.run_mode('write_image'), 1)

    @unittest.skipUnless(os.name == 'nt', 'Windows job containment')
    def test_job_close_kills_assigned_child(self):
        job = s.WindowsJob()
        child = subprocess.Popen([sys.executable,'-c','import time;time.sleep(20)'], creationflags=0x08000000)
        try:
            job.assign(child)
            job.close()
            child.wait(timeout=3)
        finally:
            job.close()
            if child.poll() is None:
                child.kill()
                child.wait()

    def test_allocated_bit_boundary(self):
        geo = {'partition_start': 0, 'cluster_size': 512, 'clusters': 24}
        bitmap = bytes([128,0,0])
        s.unallocated_range(8*512, 8*512, geo, bitmap)
        with self.assertRaises(s.CarveError):
            s.unallocated_range(6*512, 3*512, geo, bitmap)
        with self.assertRaises(s.CarveError):
            s.unallocated_range(23*512, 513, geo, bitmap)

    def test_missing_native_bitmap_name(self):
        with self.assertRaises(s.CarveError):
            s.bitmap_attribute('Allocated File\nName: $Other\n', {'minimum_bitmap_bytes': 16})

    def test_nonresident_bitmap_requires_initialized_size(self):
        text = 'Allocated File\nName: $Bitmap\nType: $DATA (128-1) Name: N/A Non-Resident size: 16\n'
        with self.assertRaisesRegex(s.CarveError, 'explicit initialized size'):
            s.bitmap_attribute(text, {'minimum_bitmap_bytes': 16})

    def test_resident_bitmap_has_no_initialized_size_field(self):
        text = 'Allocated File\nName: $Bitmap\nType: $DATA (128-1) Name: N/A Resident size: 16\n'
        self.assertEqual(s.bitmap_attribute(text, {'minimum_bitmap_bytes': 16}), ('6-128-1', 16))

    def test_fsstat_disagreement(self):
        with self.assertRaises(s.CarveError):
            s.check_fsstat('File System Type: FAT', {'sector_size':512,'cluster_size':512,'clusters':1,'ntfs_sectors':1})


if __name__ == '__main__':
    unittest.main()
