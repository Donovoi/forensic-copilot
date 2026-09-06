"""Synthetic-only tests; no evidence or external tools unless explicitly noted."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / 'scripts'))
import probe_recovered_media as media


class MediaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='media-fixture-')
        self.root = Path(self.temp.name).resolve()
        gate_path = REPO_ROOT / 'scripts/collect_image_inventory.py'
        self.batch = self.root / 'batch.json'
        self.tool_manifest = self.root / 'tools.json'
        self.state = self.root / 'media-state'
        self.c = media.Config(self.batch, '', self.tool_manifest, '', gate_path, self.state,
                              reserve_bytes=0, child_seconds=2, hash_seconds=10)
        self.gate = media.load_gate(self.c)
        self.source = self.root / 'source-state'
        self.source.mkdir()
        self.exports = self.root / 'exports'
        self.exports.mkdir()
        self.artifact = self.exports / '000000000001_0001_sample.png'
        self.artifact.write_bytes(b'\x89PNG\r\n\x1a\nsynthetic fixture bytes')
        self.image = self.root / 'must-never-open-image.raw'
        self.image.write_bytes(b'SYNTHETIC IMAGE READ SENTINEL')
        self.exit = self.root / 'producer.exit'
        self.exit.write_text('0')
        self.source_inputs = {'recovery_script_sha256': '1' * 64, 'state_dir': str(self.source),
                              'output_dir': str(self.exports), 'image_gate': {'image': str(self.image), 'sha256': '2' * 64}}
        self.source_status = {'schema_version': 1, 'phase': 'complete'}
        self.output_record = media.file_record(self.artifact, self.gate)
        self.row = {'state': 'complete', 'relative_path': self.artifact.name, 'id': 1,
                    'details': {'output_record': self.output_record, 'actual_size': self.artifact.stat().st_size,
                                'deleted': True, 'reallocated': True, 'inode_attribute': '42-128-1'}}
        self.tools = self.root / 'tools'
        self.tools.mkdir()
        groups = {}
        for name in ('exiftool', 'ffprobe'):
            folder = self.tools / name
            folder.mkdir()
            path = folder / (name + '.exe')
            path.write_bytes(b'non-executable synthetic tool identity ' + name.encode())
            groups[name] = {'root': str(folder), 'executable': path.name, 'version': 'Synthetic fixture 1',
                            'files': {path.name: media.digest(path.read_bytes())}}
        self.tool_manifest.write_text(json.dumps({'schema_version': 1, 'tools': groups}))
        self.c.tools_sha256 = media.digest(self.tool_manifest.read_bytes())
        self.write_source()

    def tearDown(self):
        self.temp.cleanup()

    def write_source(self):
        (self.source / 'inputs.json').write_text(json.dumps(self.source_inputs))
        (self.source / 'status.json').write_text(json.dumps(self.source_status))
        (self.source / 'export-attempts.jsonl').write_text(json.dumps(self.row) + '\n')
        batch = {'schema_version': 1, 'producer_kind': 'recovery', 'producer_sha256': '1' * 64,
                 'source_state': str(self.source), 'export_root': str(self.exports),
                 'source_exit': str(self.exit), 'source_exit_sha256': media.digest(self.exit.read_bytes()),
                 'source_files': {name: media.digest((self.source / name).read_bytes()) for name in
                                  ('inputs.json', 'status.json', 'export-attempts.jsonl')},
                 'artifacts': [{'source_line': 1, 'sha256': self.output_record['sha256']}]}
        self.batch.write_text(json.dumps(batch))
        self.c.batch_sha256 = media.digest(self.batch.read_bytes())

    def fake_child(self, c, gate, label, argv, directory, tool_dirs):
        directory.mkdir()
        parsed = ([{'SourceFile': argv[-1], 'File:FileType': 'PNG', 'File:MIMEType': 'image/png'}]
                  if label == 'exiftool' else {'format': {}, 'streams': [{'codec_name': 'png',
                    'codec_type': 'video', 'width': 32, 'height': 32}]})
        capture = {}
        for name, payload in [('stdout', json.dumps(parsed).encode()), ('stderr', b'')]:
            path = directory / (name + '.bin')
            path.write_bytes(payload)
            capture[name] = {'path': str(path), 'stream_bytes': len(payload), 'retained_bytes': len(payload),
                             'stream_sha256': media.digest(payload), 'truncated': False,
                             'retained_record': media.file_record(path, gate)}
        return {'state': 'probe_ok', 'label': label, 'argv': argv, 'exit_code': 0, 'parsed': parsed,
                'capture': capture, 'stop_reason': None, 'json_error': None, 'stderr_utf8': '', 'capture_errors': []}

    def latest(self):
        return json.loads(sorted((self.state / 'records').glob('*.json'))[-1].read_text())

    def test_selected_file_exact_hash_caveats_and_unchanged_resume(self):
        original = self.image.read_bytes()
        with patch.object(media, 'child', side_effect=self.fake_child) as child:
            result = media.run(self.c)
            self.assertEqual(result['phase'], 'complete')
            self.assertEqual(child.call_count, 2)
            record = self.latest()
            self.assertTrue(record['source']['source_reference']['details']['reallocated'])
            self.assertEqual(record['verified_file']['sha256'], self.output_record['sha256'])
            self.c.resume = True
            self.assertEqual(media.run(self.c)['phase'], 'complete')
            self.assertEqual(child.call_count, 2)
        self.assertEqual(self.image.read_bytes(), original)
        self.assertEqual(len(list((self.state / 'records').glob('*.json'))), 1)

    def test_dry_run_no_artifact_content_or_state(self):
        self.c.dry_run = True
        original = self.gate.protected_file
        def denied(path, *args, **kwargs):
            self.assertNotIn(Path(path), (self.image, self.artifact))
            return original(path, *args, **kwargs)
        with patch.object(media, 'load_gate', return_value=self.gate), patch.object(self.gate, 'protected_file', side_effect=denied):
            self.assertEqual(media.run(self.c)['phase'], 'dry_run')
        self.assertFalse(self.state.exists())

    def test_source_path_escape_and_image_redirect_refused_before_read(self):
        self.row['details']['output_record']['path'] = str(self.image)
        self.write_source()
        with patch.object(media, 'child') as child, self.assertRaisesRegex(media.ProbeError, 'outside canonical export'):
            media.run(self.c)
        child.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_hash_and_metadata_drift_never_reaches_parser(self):
        self.artifact.write_bytes(b'changed recovered bytes')
        with patch.object(media, 'child') as child:
            result = media.run(self.c)
        child.assert_not_called()
        self.assertEqual(result['phase'], 'complete_with_gaps')
        self.assertIn('identity/metadata differs', self.latest()['error'])

    def test_same_metadata_changed_content_fails_full_sha(self):
        before = self.artifact.stat()
        data = self.artifact.read_bytes()
        self.artifact.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
        os.utime(self.artifact, ns=(before.st_atime_ns, before.st_mtime_ns))
        with patch.object(media, 'child') as child:
            self.assertEqual(media.run(self.c)['phase'], 'complete_with_gaps')
        child.assert_not_called()
        self.assertIn('SHA256 differs', self.latest()['error'])

    def test_changed_tool_dependency_set_refused_before_artifact_read(self):
        (self.tools / 'exiftool/foreign-config.pm').write_text('synthetic unexpected module')
        with self.assertRaisesRegex(media.ProbeError, 'dependency set differs'):
            media.run(self.c)
        self.assertFalse(self.state.exists())

    def test_allocated_partial_recovery_flags_retained_without_upgrade(self):
        self.source_status['phase'] = 'complete_with_errors'
        self.exit.write_text('2')
        self.row['state'] = 'partial'
        self.row['details']['deleted'] = False
        self.write_source()
        with patch.object(media, 'child', side_effect=self.fake_child):
            self.assertEqual(media.run(self.c)['phase'], 'complete')
        self.assertEqual(self.latest()['source']['source_reference']['state'], 'partial')
        self.assertFalse(self.latest()['source']['source_reference']['details']['deleted'])

    def test_hash_time_budget_stops_before_parser(self):
        with self.gate.protected_file(self.artifact) as stream, \
                patch.object(media.time, 'monotonic', side_effect=[0, 1]), \
                self.assertRaisesRegex(media.BudgetStop, 'time budget'):
            media.hash_stream(stream, self.gate, 0.001, media.MIB)

    def test_hardlinked_artifact_refused(self):
        os.link(self.artifact, self.root / 'other-hardlink.png')
        with patch.object(media, 'child') as child:
            self.assertEqual(media.run(self.c)['phase'], 'complete_with_gaps')
        child.assert_not_called()
        self.assertIn('one hard link', self.latest()['error'])

    def test_orphan_attempt_directory_retained_and_new_attempt_used(self):
        with patch.object(media, 'child', return_value={'state': 'probe_incomplete'}):
            media.run(self.c)
        orphan = self.state / 'attempts/000000001_00002'
        orphan.mkdir()
        marker = orphan / 'partial-output.txt'
        marker.write_text('interrupted native fixture output')
        self.c.resume = True
        with patch.object(media, 'child', side_effect=self.fake_child):
            self.assertEqual(media.run(self.c)['phase'], 'complete')
        self.assertTrue((self.state / 'records/000000001_00003.json').exists())
        self.assertEqual(marker.read_text(), 'interrupted native fixture output')

    def test_source_producer_or_manifest_hash_mismatch_refused(self):
        self.source_inputs['recovery_script_sha256'] = '3' * 64
        self.write_source()
        with self.assertRaisesRegex(media.ProbeError, 'producer hash mismatch'):
            media.run(self.c)
        self.source_inputs['recovery_script_sha256'] = '1' * 64
        self.write_source()
        with (self.source / 'export-attempts.jsonl').open('a') as stream:
            stream.write('\n')
        with self.assertRaisesRegex(media.ProbeError, 'provenance hash mismatch'):
            media.run(self.c)

    def test_unknown_signature_retained_and_no_parser_called(self):
        self.artifact.write_bytes(b'#EXTM3U\nhttps://invalid.example/synthetic.ts\n')
        self.output_record = media.file_record(self.artifact, self.gate)
        self.row['details'].update(output_record=self.output_record, actual_size=self.output_record['size'])
        self.write_source()
        with patch.object(media, 'child') as child:
            result = media.run(self.c)
        child.assert_not_called()
        self.assertEqual(result['phase'], 'complete_with_gaps')
        self.assertEqual(self.latest()['state'], 'deferred_unsupported_signature')
        self.assertEqual(self.latest()['verified_file']['sha256'], self.output_record['sha256'])

    def test_incomplete_probe_is_retried_on_resume(self):
        with patch.object(media, 'child', return_value={'state': 'probe_incomplete', 'stop_reason': 'timeout'}) as child:
            self.assertEqual(media.run(self.c)['phase'], 'complete_with_gaps')
            self.c.resume = True
            self.assertEqual(media.run(self.c)['phase'], 'complete_with_gaps')
            self.assertEqual(child.call_count, 4)
        self.assertEqual(len(list((self.state / 'records').glob('*.json'))), 2)

    def test_changed_batch_resume_invalidates_success(self):
        with patch.object(media, 'child', side_effect=self.fake_child):
            media.run(self.c)
        self.c.resume = True
        with self.batch.open('a') as stream:
            stream.write('\n')
        with self.assertRaisesRegex(media.ProbeError, 'batch hash mismatch'):
            media.run(self.c)
        self.assertFalse(json.loads((self.state / 'status.json').read_text())['analysis_complete'])

    def test_changed_or_deleted_capture_causes_new_attempt(self):
        with patch.object(media, 'child', side_effect=self.fake_child) as child:
            media.run(self.c)
            self.c.resume = True
            stdout = self.state / 'attempts/000000001_00001/ffprobe/stdout.bin'
            stdout.write_text('{}')
            self.assertEqual(media.run(self.c)['phase'], 'complete')
            self.assertEqual(child.call_count, 4)
            stderr = self.state / 'attempts/000000001_00002/ffprobe/stderr.bin'
            stderr.unlink()
            self.assertEqual(media.run(self.c)['phase'], 'complete')
            self.assertEqual(child.call_count, 6)
        self.assertEqual(stdout.read_text(), '{}')
        self.assertEqual(len(list((self.state / 'records').glob('*.json'))), 3)

    def test_changed_or_missing_success_record_never_reused(self):
        with patch.object(media, 'child', side_effect=self.fake_child) as child:
            media.run(self.c)
            self.c.resume = True
            record_path = self.state / 'records/000000001_00001.json'
            original = json.loads(record_path.read_text())
            original['children'] = {}
            record_path.write_text(json.dumps(original))
            self.assertEqual(media.run(self.c)['phase'], 'complete')
            self.assertEqual(child.call_count, 4)
            (self.state / 'records/000000001_00002.json').unlink()
            self.assertEqual(media.run(self.c)['phase'], 'complete')
            self.assertEqual(child.call_count, 6)
        self.assertEqual(json.loads(record_path.read_text())['children'], {})
        self.assertTrue((self.state / 'records/000000001_00003.json').exists())

    def test_indexed_empty_child_structure_still_cannot_be_reused(self):
        with patch.object(media, 'child', side_effect=self.fake_child) as child:
            media.run(self.c)
            record_path = self.state / 'records/000000001_00001.json'
            original = json.loads(record_path.read_text())
            original['children'] = {}
            record_path.write_text(json.dumps(original))
            index_path = self.state / 'records-index.json'
            index = json.loads(index_path.read_text())
            index[record_path.name] = media.file_record(record_path, self.gate)
            index_path.write_text(json.dumps(index))
            self.c.resume = True
            self.assertEqual(media.run(self.c)['phase'], 'complete')
            self.assertEqual(child.call_count, 4)

    def test_hash_size_budget_and_free_reserve_are_explicit_gaps(self):
        self.c.max_file_bytes = 1
        with patch.object(media, 'child') as child:
            self.assertEqual(media.run(self.c)['phase'], 'complete_with_gaps')
        child.assert_not_called()
        self.assertEqual(self.latest()['state'], 'deferred_resource')

    def test_fixed_commands_disallow_executable_demuxers_and_external_refs(self):
        cmds = media.commands({'ffprobe': ['ffprobe.exe'], 'exiftool': ['exiftool.exe']}, self.artifact, 'mov')
        ff = cmds['ffprobe']
        self.assertEqual(ff[ff.index('-f') + 1], 'mov')
        self.assertEqual(ff[ff.index('-protocol_whitelist') + 1], 'file')
        self.assertEqual(ff[ff.index('-format_whitelist') + 1], 'mov')
        self.assertEqual(ff[ff.index('-enable_drefs') + 1], '0')
        self.assertEqual(ff[ff.index('-use_absolute_path') + 1], '0')
        self.assertEqual(cmds['exiftool'][1:3], ['-config', ''])
        for forbidden in ('image2', 'avisynth', 'concat', 'hls', 'dash', '-show_frames', '-show_packets', '-ee', '-stay_open'):
            self.assertNotIn(forbidden, ff + cmds['exiftool'])

    def test_signature_whitelist_uses_binary_headers_not_extensions(self):
        for header, expected in [(b'\x89PNG\r\n\x1a\n', 'png_pipe'), (b'\xff\xd8\xff\xe0', 'jpeg_pipe'),
                                 (b'RIFF\0\0\0\0WAVE', 'wav'),
                                 (b'\0\0\0\x18ftypisom\0\0\0\0', 'mov'),
                                 (b'RIFF\0\0\0\0AVI ', None), (b'AviSource("sentinel.avi")', None),
                                 (b'ffconcat version 1.0', None), (b'<MPD>', None), (b'MZ', None)]:
            self.assertEqual(media.signature(header), expected)

    @unittest.skipUnless(os.name == 'nt', 'Windows native process containment')
    def test_child_timeout_capture_limit_and_memory_job(self):
        self.state.mkdir()
        programs = [('timeout', 'import time;time.sleep(30)', 'timeout'),
                    ('stdout', 'import sys;sys.stdout.buffer.write(b"x"*1000000)', 'capture_limit_or_failure'),
                    ('memory', 'x=bytearray(1024*1024*1024)', None)]
        self.c.child_seconds = 0.4
        self.c.stdout_bytes = 8192
        self.c.memory_bytes = 128 * media.MIB
        for label, program, reason in programs:
            result = media.child(self.c, self.gate, 'ffprobe', [str(Path(sys.executable).resolve()), '-c', program],
                                 self.state / label, [Path(sys.executable).parent])
            self.assertEqual(result['state'], 'probe_incomplete')
            if reason:
                self.assertEqual(result['stop_reason'], reason)
            self.assertLessEqual(result['capture']['stdout']['retained_bytes'], 8192)
            if label == 'memory':
                self.assertNotEqual(result['exit_code'], 0, repr(result))


if __name__ == '__main__':
    unittest.main()
