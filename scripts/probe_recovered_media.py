#!/usr/bin/env python3
"""Bounded metadata/header probes of explicitly selected, hash-bound recovered files.

Authored 2026-09-07; Windows/Python 3.10+ stdlib. No raw-image API is called.
Pending independent review. Case-local outputs are private evidence derivatives.
"""
from __future__ import annotations
import argparse
import contextlib
import ctypes
from dataclasses import dataclass
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
import types

MIB = 1024 ** 2
MANIFEST_BUFFER_BYTES = 64 * 1024
GIB = 1024 ** 3
HEADER_BYTES = 65536
SIGNATURE_POLICY = 'bounded-media-families-v1'
CARVER_SHA256 = 'c42a94c53eb1b6d650be7fba14f1230a62875b5b0cdf5c1089c6f71ac8aa4676'
DEMUXERS = ('png_pipe', 'jpeg_pipe', 'wav', 'mov', 'mp3', 'mpeg', 'mpegvideo', 'avi', 'asf', 'flv')
GATE_SHA256 = '5b8089929c4586c68403b5d0c37b6b88d6b632b1097e1e7a7f68d1d99e348a5e'
LIMITATIONS = [
    'Bounded metadata and stream-header probes only; no full-file decode or media authenticity finding.',
    'Metadata timestamps retain tool values; timezone, clock accuracy and historical attribution are not established.',
    'Deleted/reallocated content and unmapped thumbnail caveats remain unchanged by a successful probe.',
    'Only bounded signature-gated PNG/JPEG/WAVE, recognized ftyp MP4/MOV/M4A/3GP, LayerIII MP3, MPEG PS/video, AVI, ASF and FLV candidates are probed.',
    'Oversized ID3/ASF headers, free-format MP3, unsupported brands and ambiguous/truncated headers remain coverage gaps.',
    'Unknown signatures, resource limits and parser failures are coverage gaps, not proof of invalid original media.',
    'ExifTool fast2 deliberately omits MakerNotes and metadata after image/media data in some containers.',
    'Protocol/demuxer restrictions are parser controls, not an OS security sandbox against native-library vulnerabilities.',
]


class ProbeError(RuntimeError):
    pass


class BudgetStop(ProbeError):
    pass


@dataclass
class Config:
    batch: Path
    batch_sha256: str
    tools_manifest: Path
    tools_sha256: str
    gate_module: Path
    state_dir: Path
    resume: bool = False
    dry_run: bool = False
    max_file_bytes: int = 16 * GIB
    hash_seconds: float = 1800
    child_seconds: float = 60
    total_seconds: float = 6 * 3600
    memory_bytes: int = 512 * MIB
    stdout_bytes: int = MIB
    stderr_bytes: int = 65536
    max_state_bytes: int = 512 * MIB
    reserve_bytes: int = 64 * GIB


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(payload):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ProbeError('Duplicate JSON key')
            result[key] = value
        return result
    try:
        return json.loads(payload.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=lambda value: (_ for _ in ()).throw(ProbeError('Nonfinite JSON number')))
    except (ValueError, UnicodeDecodeError, RecursionError) as error:
        raise ProbeError('Invalid bounded UTF-8 JSON') from error


def load_gate(c):
    payload = c.gate_module.read_bytes()
    if digest(payload) != GATE_SHA256:
        raise ProbeError('Approved path/locking helper hash mismatch')
    module = types.ModuleType('_media_path_gate')
    module.__file__ = str(c.gate_module)
    sys.modules[module.__name__] = module
    exec(compile(payload, str(c.gate_module), 'exec'), module.__dict__)
    return module


def inside(path, root):
    return path == root or root in path.parents


def lexical_path(value):
    if not isinstance(value, (str, Path)) or not os.path.isabs(value):
        raise ProbeError('Require explicit absolute local paths')
    path = Path(value)
    if str(path).startswith(('\\\\', '//')) or ':' in str(path)[2:]:
        raise ProbeError('UNC, device and alternate-stream paths are refused')
    return path


def local_path(value, gate):
    path = lexical_path(value)
    gate.require_unaliased(path)
    if os.name == 'nt' and ctypes.windll.kernel32.GetDriveTypeW(path.anchor) != 3:
        raise ProbeError('Only fixed local volumes are supported')
    return path


def regular(path, gate):
    local_path(path, gate)
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise ProbeError('Require a regular recovered/input file with one hard link and no reparse point')
    return gate.metadata(info)


def hash_stream(stream, gate, seconds, max_bytes):
    before = gate.metadata(os.fstat(stream.fileno()))
    if before['size'] > max_bytes:
        raise BudgetStop('Full-file hash deferred: file exceeds byte budget')
    started, count, hashed = time.monotonic(), 0, hashlib.sha256()
    stream.seek(0)
    while block := stream.read(MIB):
        count += len(block)
        if count > max_bytes or time.monotonic() - started > seconds:
            raise BudgetStop('Full-file hash deferred: byte/time budget')
        hashed.update(block)
    if count != before['size'] or gate.metadata(os.fstat(stream.fileno())) != before:
        raise ProbeError('File changed during full hashing')
    return {'metadata': before, 'sha256': hashed.hexdigest(), 'size': count}


def file_record(path, gate, seconds=120, max_bytes=512 * MIB):
    regular(path, gate)
    with gate.protected_file(path) as stream:
        record = hash_stream(stream, gate, seconds, max_bytes)
    if regular(path, gate) != record['metadata']:
        raise ProbeError('Path identity changed during hashing')
    return {'path': str(path), **record}


def json_file(path, gate, limit=MIB):
    regular(path, gate)
    with gate.protected_file(path) as stream:
        payload = stream.read(limit + 1)
        if len(payload) > limit:
            raise ProbeError('JSON exceeds configured byte bound')
        metadata = gate.metadata(os.fstat(stream.fileno()))
    return strict_json(payload), {'path': str(path), 'metadata': metadata, 'size': len(payload), 'sha256': digest(payload)}


@contextlib.contextmanager
def buffered_manifest(path, gate):
    with gate.protected_file(path) as raw:
        stream = io.BufferedReader(raw, buffer_size=MANIFEST_BUFFER_BYTES)
        try:
            yield stream
        finally:
            stream.detach()  # Preserve original protected-context lock/close ownership.


def bind_source(c, gate, locks):
    batch, batch_record = json_file(c.batch, gate)
    if batch_record['sha256'] != c.batch_sha256.lower():
        raise ProbeError('Approved batch hash mismatch')
    required = {'schema_version', 'producer_kind', 'producer_sha256', 'source_state', 'source_files',
                'source_exit', 'source_exit_sha256', 'export_root', 'artifacts'}
    if not isinstance(batch, dict) or set(batch) != required or type(batch['schema_version']) is not int or batch['schema_version'] != 1:
        raise ProbeError('Unsupported batch schema')
    kind = batch['producer_kind']
    if kind not in ('recovery', 'photorec') or not re.fullmatch('[a-f0-9]{64}', batch['producer_sha256']):
        raise ProbeError('Unsupported producer identity')
    source = local_path(batch['source_state'], gate)
    exports = local_path(batch['export_root'], gate)
    exit_path = local_path(batch['source_exit'], gate)
    manifest_name = 'export-attempts.jsonl' if kind == 'recovery' else 'output-manifest.jsonl'
    if not isinstance(batch['source_files'], dict) or set(batch['source_files']) != {'inputs.json', 'status.json', manifest_name}:
        raise ProbeError('Exact producer inputs/status/output manifest hashes are required')
    for protected in (source, exports, exit_path, c.batch, c.tools_manifest, c.gate_module):
        if inside(c.state_dir, protected) or inside(protected, c.state_dir):
            raise ProbeError('Media state overlaps protected inputs or exports')
    records = {}
    for name, expected in batch['source_files'].items():
        path = source / name
        regular(path, gate)
        locks.enter_context(gate.protected_file(path))
        record = file_record(path, gate, c.hash_seconds, 1024 * MIB)
        if record['sha256'] != expected:
            raise ProbeError('Producer provenance hash mismatch: ' + name)
        records[name] = record
    locks.enter_context(gate.protected_file(exit_path))
    exit_record = file_record(exit_path, gate, max_bytes=65536)
    if exit_record['sha256'] != batch['source_exit_sha256']:
        raise ProbeError('Producer exit-marker hash mismatch')
    producer, _ = json_file(source / 'inputs.json', gate)
    status, _ = json_file(source / 'status.json', gate)
    with gate.protected_file(exit_path) as stream:
        exit_bytes = stream.read(65537)
    if kind == 'recovery':
        if producer.get('recovery_script_sha256') != batch['producer_sha256']:
            raise ProbeError('Recovery producer hash mismatch')
        configuration = producer
        if status.get('phase') not in ('complete', 'complete_with_errors', 'deferred', 'failed'):
            raise ProbeError('Recovery producer is not at a closed stage')
        try:
            code = int(exit_bytes.decode('ascii').strip())
        except ValueError as error:
            raise ProbeError('Invalid recovery exit marker') from error
        if code not in (0, 1, 2, 130) or (status['phase'] == 'complete') != (code == 0):
            raise ProbeError('Recovery status and exit disagree')
    else:
        if producer.get('runner_sha256') != batch['producer_sha256'] or batch['producer_sha256'] != CARVER_SHA256:
            raise ProbeError('Carver producer hash mismatch')
        configuration = producer.get('configuration', {})
        exited = strict_json(exit_bytes)
        if (status.get('phase') != 'complete' or status.get('scan_completed') is not True or
                exited.get('exit_code') != 0 or exited.get('phase') != 'complete'):
            raise ProbeError('Only completed hash-manifest carver outputs are supported; partial metadata-only rows deferred')
        if configuration != status.get('configuration'):
            raise ProbeError('Carver configuration sidecars disagree')
        recorded = status.get('output_manifest', {})
        if recorded.get('sha256') != records[manifest_name]['sha256'] or recorded.get('bytes') != records[manifest_name]['size']:
            raise ProbeError('Carver status does not bind its output manifest')
        if local_path(recorded.get('path'), gate) != source / manifest_name:
            raise ProbeError('Carver output manifest path mismatch')
    if local_path(configuration.get('state_dir'), gate) != source or local_path(configuration.get('output_dir'), gate) != exports:
        raise ProbeError('Producer state/export root mismatch')
    image_gate = producer.get('image_gate', {})
    image_name = image_gate.get('image')
    if not isinstance(image_name, str) or inside(exports, Path(image_name)) or inside(Path(image_name), exports):
        raise ProbeError('Export root overlaps producer image or has missing image identity')
    selected = batch['artifacts']
    if not isinstance(selected, list) or not 1 <= len(selected) <= 10000:
        raise ProbeError('Select between one and 10000 exact source rows')
    requested = {}
    for item in selected:
        if not isinstance(item, dict) or set(item) != {'source_line', 'sha256'}:
            raise ProbeError('Each selection requires only source_line and sha256')
        number = item['source_line']
        if type(number) is not int or not 1 <= number <= 999999999 or number in requested or not re.fullmatch('[a-f0-9]{64}', item['sha256']):
            raise ProbeError('Invalid or duplicate source-row selection')
        requested[number] = item['sha256']
    rows, retained = [], 0
    with buffered_manifest(source / manifest_name, gate) as stream:
        number = 0
        while raw := stream.readline(MIB + 1):
            number += 1
            if len(raw) > MIB:
                raise ProbeError('Producer output row exceeds one MiB')
            if number not in requested:
                continue
            retained += len(raw)
            if retained > 16 * MIB:
                raise ProbeError('Selected provenance rows exceed 16 MiB; use smaller batches')
            row = strict_json(raw)
            if kind == 'recovery':
                details = row.get('details', {})
                record = details.get('output_record', {})
                if row.get('state') not in ('complete', 'partial', 'failed', 'interrupted'):
                    raise ProbeError('Selected recovery attempt is unfinished or has no closed bytes')
                path = lexical_path(record.get('path'))
                if path.parent != exports or path.name != row.get('relative_path'):
                    raise ProbeError('Recovery artifact is outside canonical export root')
                size = details.get('actual_size')
                if record.get('metadata', {}).get('size') != size:
                    raise ProbeError('Recovery size and recorded output metadata disagree')
            else:
                record = row
                path = lexical_path(record.get('path'))
                if path.parent.parent != exports or not re.fullmatch(r'recup\.[1-9][0-9]*', path.parent.name):
                    raise ProbeError('Carved artifact is outside canonical recovery directory')
                size = row.get('size')
                if row.get('image_sha256') != image_gate.get('sha256'):
                    raise ProbeError('Carver row image identity differs from producer')
            if not inside(path, exports) or path == Path(image_name):
                raise ProbeError('Source row points outside recovered outputs')
            local_path(path, gate)
            if type(size) is not int or size < 0 or record.get('sha256') != requested[number]:
                raise ProbeError('Selected artifact lacks its expected full hash/size')
            if not isinstance(record.get('metadata'), dict) or record['metadata'].get('size') != size:
                raise ProbeError('Selected artifact lacks producer output metadata')
            rows.append({'source_line': number, 'source_row_sha256': digest(raw), 'source_reference': row,
                         'path': str(path), 'sha256': requested[number], 'size': size, 'metadata': record['metadata']})
    if len(rows) != len(requested):
        raise ProbeError('One or more requested producer rows are missing')
    return rows, {'batch': batch_record, 'producer_kind': kind, 'producer_sha256': batch['producer_sha256'],
                  'source_files': records, 'source_exit': exit_record, 'image_identity': image_gate,
                  'source_phase': status['phase'], 'export_root': str(exports)}


def mp3_frame(header, offset):
    if offset + 4 > len(header):
        return None
    h = int.from_bytes(header[offset:offset + 4], 'big')
    version, layer, rate, sample = (h >> 19) & 3, (h >> 17) & 3, (h >> 12) & 15, (h >> 10) & 3
    if h & 0xFFE00000 != 0xFFE00000 or version == 1 or layer != 1 or rate in (0, 15) or sample == 3 or h & 3 == 2:
        return None
    kbps = ((0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320)[rate] if version == 3 else
            (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160)[rate])
    hz = (44100, 48000, 32000)[sample] // (1 if version == 3 else 2 if version == 2 else 4)
    length = (144 if version == 3 else 72) * kbps * 1000 // hz + ((h >> 9) & 1)
    return length, version, layer, hz


def mp3_signature(header):
    offset = 0
    if header.startswith(b'ID3'):
        if len(header) < 10 or header[3] not in (2, 3, 4) or header[4] == 255 or any(v & 128 for v in header[6:10]):
            return False
        mask = {2: 0xC0, 3: 0xE0, 4: 0xF0}[header[3]]
        if header[5] & ~mask:
            return False
        tag_size = sum(v << shift for v, shift in zip(header[6:10], (21, 14, 7, 0)))
        offset = 10 + tag_size
        if header[3] == 4 and header[5] & 0x10:
            if offset + 10 > len(header) or header[offset:offset + 3] != b'3DI' or header[offset + 3:offset + 10] != header[3:10]:
                return False
            offset += 10
    first = mp3_frame(header, offset)
    if first is None or offset + first[0] + 4 > len(header):
        return False
    second = mp3_frame(header, offset + first[0])
    return second is not None and first[1:] == second[1:] and offset + first[0] + second[0] <= len(header)


def asf_signature(header):
    if len(header) < 30 or header[:16] != bytes.fromhex('3026b2758e66cf11a6d900aa0062ce6c'):
        return False
    end, count = int.from_bytes(header[16:24], 'little'), int.from_bytes(header[24:28], 'little')
    if not 30 <= end <= len(header) or not 1 <= count <= 2048 or header[28:30] != b'\x01\x02':
        return False
    offset = 30
    for unused in range(count):
        if offset + 24 > end:
            return False
        length = int.from_bytes(header[offset + 16:offset + 24], 'little')
        if length < 24 or offset + length > end or header[offset:offset + 16] == bytes(16):
            return False
        offset += length
    return offset == end


def signature(header):
    if len(header) > HEADER_BYTES:
        return None
    if header.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'png_pipe'
    if header.startswith(b'\xff\xd8\xff'):
        return 'jpeg_pipe'
    if len(header) >= 12 and header[:4] == b'RIFF' and header[8:12] == b'WAVE':
        return 'wav'
    if len(header) >= 16 and header[4:8] == b'ftyp' and 16 <= int.from_bytes(header[:4], 'big') <= min(4096, len(header)):
        if header[8:12] in (b'isom', b'iso2', b'mp41', b'mp42', b'avc1', b'M4V ', b'M4A ', b'qt  ',
                            b'3gp4', b'3gp5', b'3gp6', b'3gp7', b'3ge6', b'3gg6', b'3g2a', b'3g2b', b'3g2c'):
            return 'mov'
    if mp3_signature(header):
        return 'mp3'
    if len(header) >= 15 and header[:4] == b'\x00\x00\x01\xba':
        if (header[4] & 0xF1 == 0x21 and header[6] & 1 and header[8] & 1 and
                header[9] & 0x80 and header[11] & 1 and header[12:15] == b'\x00\x00\x01'):
            return 'mpeg'
        if (len(header) >= 17 and header[4] & 0xC4 == 0x44 and header[6] & 4 and header[8] & 4 and
                header[9] & 1 and header[12] & 3 == 3 and header[13] & 0xF8 == 0xF8):
            offset = 14 + (header[13] & 7)
            if offset + 3 <= len(header) and header[offset:offset + 3] == b'\x00\x00\x01':
                return 'mpeg'
    if len(header) >= 12 and header[:4] == b'\x00\x00\x01\xb3':
        width, height = int.from_bytes(header[4:6], 'big') >> 4, int.from_bytes(header[5:7], 'big') & 4095
        if width and height and 1 <= header[7] >> 4 <= 14 and 1 <= header[7] & 15 <= 8 and header[10] & 0x20:
            return 'mpegvideo'
    if (len(header) >= 24 and header[:4] == b'RIFF' and int.from_bytes(header[4:8], 'little') >= 56 and
            header[8:16] == b'AVI LIST' and int.from_bytes(header[16:20], 'little') >= 4 and header[20:24] == b'hdrl'):
        return 'avi'
    if asf_signature(header):
        return 'asf'
    if len(header) >= 13 and header[:4] == b'FLV\x01' and header[4] in (1, 4, 5):
        offset = int.from_bytes(header[5:9], 'big')
        if 9 <= offset <= len(header) - 4 and header[offset:offset + 4] == bytes(4):
            return 'flv'
    return None


def commands(tools, path, demuxer):
    if demuxer not in DEMUXERS:
        raise ProbeError('Demuxer outside the explicit signature policy')
    ffprobe = [*tools['ffprobe'], '-hide_banner', '-v', 'warning', '-protocol_whitelist', 'file',
               '-format_whitelist', demuxer, '-f', demuxer, '-max_alloc', str(64 * MIB),
               '-probesize', str(MIB), '-analyzeduration', '1000000', '-max_streams', '64', '-threads', '1']
    if demuxer == 'mov':
        ffprobe += ['-enable_drefs', '0', '-use_absolute_path', '0']
    ffprobe += ['-show_entries',
                'format=format_name,duration,size,bit_rate:format_tags=creation_time:'
                'stream=index,codec_name,codec_type,width,height,sample_rate,channels,duration,nb_frames:'
                'stream_tags=creation_time:stream_side_data=rotation:error=code,string',
                '-show_error', '-of', 'json', str(path)]
    exiftool = [*tools['exiftool'], '-config', '', '-j', '-G1', '-n', '-fast2',
                '-FileType', '-MIMEType', '-ImageWidth', '-ImageHeight', '-Duration',
                '-Make', '-Model', '-Software', '-DateTimeOriginal', '-CreateDate', '-ModifyDate',
                '-OffsetTime', '-OffsetTimeOriginal', '-OffsetTimeDigitized',
                '-GPSLatitude', '-GPSLongitude', '-GPSAltitude', '-GPSDateStamp', '-GPSTimeStamp',
                '-Orientation', '-Warning', '-Error', str(path)]
    return {'exiftool': exiftool, 'ffprobe': ffprobe}


class WindowsJob:
    """Assign a suspended child before parser execution; cap aggregate committed memory."""
    def __init__(self, memory_bytes):
        if os.name != 'nt':
            raise ProbeError('This reviewed child containment route requires Windows')
        from ctypes import wintypes as w
        self.w = w
        class Basic(ctypes.Structure):
            _fields_ = [('process_time', ctypes.c_int64), ('job_time', ctypes.c_int64), ('flags', w.DWORD),
                        ('min_working', ctypes.c_size_t), ('max_working', ctypes.c_size_t),
                        ('active_limit', w.DWORD), ('affinity', ctypes.c_size_t),
                        ('priority', w.DWORD), ('scheduling', w.DWORD)]
        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in ('read_ops', 'write_ops', 'other_ops',
                                                            'read_bytes', 'write_bytes', 'other_bytes')]
        class Extended(ctypes.Structure):
            _fields_ = [('basic', Basic), ('io', IO), ('process_memory', ctypes.c_size_t),
                        ('job_memory', ctypes.c_size_t), ('peak_process', ctypes.c_size_t), ('peak_job', ctypes.c_size_t)]
        self.kernel = k = ctypes.WinDLL('kernel32', use_last_error=True)
        k.CreateJobObjectW.argtypes, k.CreateJobObjectW.restype = [ctypes.c_void_p, w.LPCWSTR], w.HANDLE
        k.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
        k.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        k.CloseHandle.argtypes = [w.HANDLE]
        self.handle = k.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = Extended()
        limits.basic.flags = 0x2000 | 0x100 | 0x200 | 0x8  # kill-on-close, process/job memory, active process cap
        limits.basic.active_limit = 4  # ExifTool launcher plus bundled Perl is permitted.
        limits.process_memory = limits.job_memory = memory_bytes
        if not k.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise ctypes.WinError(ctypes.get_last_error())

    def start(self, process):
        k, w = self.kernel, self.w
        if not k.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise ctypes.WinError(ctypes.get_last_error())
        class ThreadEntry(ctypes.Structure):
            _fields_ = [('size', w.DWORD), ('usage', w.DWORD), ('thread_id', w.DWORD),
                        ('owner_pid', w.DWORD), ('base_priority', w.LONG), ('delta_priority', w.LONG), ('flags', w.DWORD)]
        k.CreateToolhelp32Snapshot.argtypes, k.CreateToolhelp32Snapshot.restype = [w.DWORD, w.DWORD], w.HANDLE
        k.Thread32First.argtypes = k.Thread32Next.argtypes = [w.HANDLE, ctypes.POINTER(ThreadEntry)]
        k.OpenThread.argtypes, k.OpenThread.restype = [w.DWORD, w.BOOL, w.DWORD], w.HANDLE
        k.ResumeThread.argtypes, k.ResumeThread.restype = [w.HANDLE], w.DWORD
        snapshot = k.CreateToolhelp32Snapshot(4, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            entry = ThreadEntry()
            entry.size = ctypes.sizeof(entry)
            found = k.Thread32First(snapshot, ctypes.byref(entry))
            while found:
                if entry.owner_pid == process.pid:
                    handle = k.OpenThread(2, False, entry.thread_id)  # THREAD_SUSPEND_RESUME
                    if not handle:
                        raise ctypes.WinError(ctypes.get_last_error())
                    try:
                        if k.ResumeThread(handle) != 1:
                            raise ProbeError('Unexpected primary-thread suspension count')
                    finally:
                        k.CloseHandle(handle)
                    return
                found = k.Thread32Next(snapshot, ctypes.byref(entry))
            raise ProbeError('Suspended child primary thread not found')
        finally:
            k.CloseHandle(snapshot)

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def child_environment(cwd, tool_dirs):
    system = Path(os.environ.get('SystemRoot', 'C:/Windows'))
    # No inherited FFREPORT, Perl/Python loader flags, proxy settings or analyst config homes.
    return {'SystemRoot': str(system), 'WINDIR': str(system),
            'PATH': os.pathsep.join([*(str(path) for path in tool_dirs), str(system / 'System32')]),
            'HOME': str(cwd), 'USERPROFILE': str(cwd), 'TMP': str(cwd), 'TEMP': str(cwd),
            '__COMPAT_LAYER': 'RunAsInvoker', 'TZ': 'UTC', 'AV_LOG_FORCE_NOCOLOR': '1'}


def usable_json(label, parsed, path, gate):
    if label == 'exiftool':
        shape_ok = isinstance(parsed, list) and len(parsed) == 1 and isinstance(parsed[0], dict)
        diagnostic = shape_ok and any(key.split(':')[-1] in ('Warning', 'Error') for key in parsed[0])
        shape_ok = (shape_ok and isinstance(parsed[0].get('SourceFile'), str) and
                    gate.same_path(parsed[0]['SourceFile'], path) and
                    isinstance(parsed[0].get('File:FileType'), str) and isinstance(parsed[0].get('File:MIMEType'), str))
    else:
        shape_ok = isinstance(parsed, dict) and isinstance(parsed.get('streams'), list) and isinstance(parsed.get('format'), dict)
        media_streams = ([value for value in parsed['streams'] if isinstance(value, dict) and
                         value.get('codec_type') in ('audio', 'video')] if shape_ok else [])
        shape_ok = bool(media_streams)
        for value in media_streams:
            if not isinstance(value.get('codec_name'), str) or value['codec_name'] in ('', 'unknown'):
                shape_ok = False
            if value['codec_type'] == 'video':
                if any(type(value.get(key)) is not int or value[key] <= 0 for key in ('width', 'height')):
                    shape_ok = False
            elif (type(value.get('channels')) is not int or value['channels'] <= 0 or
                    not str(value.get('sample_rate', '')).isdigit() or int(value['sample_rate']) <= 0):
                shape_ok = False
        diagnostic = isinstance(parsed, dict) and 'error' in parsed
    return bool(shape_ok and not diagnostic)


def child(c, gate, label, argv, directory, tool_dirs):
    base_state_bytes = state_usage(c.state_dir, gate)
    directory.mkdir()
    cwd = directory / 'cwd'
    cwd.mkdir()
    results, errors, stop = {}, [], threading.Event()
    def pump(name, pipe, limit):
        path = directory / (name + '.bin')
        count, kept, h = 0, 0, hashlib.sha256()
        try:
            with path.open('xb') as sink:
                while block := pipe.read(65536):
                    count += len(block)
                    h.update(block)
                    saved = block[:max(0, limit - kept)]
                    sink.write(saved)
                    kept += len(saved)
                    if count > limit:
                        stop.set()
                sink.flush()
                os.fsync(sink.fileno())
        except BaseException as error:
            errors.append(type(error).__name__ + ': ' + str(error))
            stop.set()
        finally:
            pipe.close()
            results[name] = {'path': str(path), 'stream_bytes': count, 'retained_bytes': kept,
                             'stream_sha256': h.hexdigest(), 'truncated': count != kept}
    started, process, threads, reason = time.monotonic(), None, [], None
    last_storage_check = started
    job = WindowsJob(c.memory_bytes)
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   cwd=cwd, env=child_environment(cwd, tool_dirs), shell=False,
                                   creationflags=0x08000004)  # CREATE_NO_WINDOW | CREATE_SUSPENDED
        for name, pipe, limit in [('stdout', process.stdout, c.stdout_bytes), ('stderr', process.stderr, c.stderr_bytes)]:
            thread = threading.Thread(target=pump, args=(name, pipe, limit), daemon=True)
            thread.start()
            threads.append(thread)
        job.start(process)
        while process.poll() is None:
            if stop.is_set():
                reason = 'capture_limit_or_failure'
                break
            if time.monotonic() - started > c.child_seconds:
                reason = 'timeout'
                break
            if shutil.disk_usage(c.state_dir).free < c.reserve_bytes + 4 * MIB:
                reason = 'free_space_reserve'
                break
            if time.monotonic() - last_storage_check >= 0.5:
                if base_state_bytes + state_usage(directory, gate) > c.max_state_bytes:
                    reason = 'state_byte_stop_threshold'
                    break
                last_storage_check = time.monotonic()
            time.sleep(0.05)
    finally:
        job.close()  # Also ends any remaining descendants that hold captured pipes.
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
        for thread in threads:
            thread.join(timeout=10)
        if any(thread.is_alive() for thread in threads):
            raise ProbeError('Child output readers did not terminate')
    if stop.is_set():
        reason = reason or 'capture_limit_or_failure'
    stdout = (directory / 'stdout.bin').read_bytes()
    stderr = (directory / 'stderr.bin').read_bytes()
    for name, captured in results.items():
        captured['retained_record'] = file_record(directory / (name + '.bin'), gate, c.hash_seconds,
                                                 c.stdout_bytes if name == 'stdout' else c.stderr_bytes)
    parsed, parse_error = None, None
    try:
        parsed = strict_json(stdout)
    except ProbeError as error:
        parse_error = str(error)
    state = ('probe_ok' if process.returncode == 0 and not reason and not stderr and usable_json(label, parsed, argv[-1], gate)
             else 'probe_incomplete')
    return {'label': label, 'argv': argv, 'exit_code': process.returncode, 'state': state,
            'stop_reason': reason, 'elapsed_seconds': time.monotonic() - started, 'capture': results,
            'parsed': parsed, 'json_error': parse_error, 'capture_errors': errors,
            'stderr_utf8': stderr.decode('utf-8', errors='replace')}


def reusable_record(c, gate, record_path, index, row, full, tools, header_record, demuxer):
    """Prior JSON and every retained capture must be provably intact before reuse."""
    if record_path.name not in index:
        return False
    actual_record = file_record(record_path, gate, c.hash_seconds, 64 * MIB)
    if actual_record != index[record_path.name]:
        return False
    prior, _ = json_file(record_path, gate, 64 * MIB)
    if (prior.get('state') != 'probe_ok' or prior.get('source') != row or prior.get('verified_file') != full or
            prior.get('signature_candidate') not in DEMUXERS or prior.get('signature_candidate') != demuxer or
            prior.get('signature_header') != header_record or
            type(prior.get('attempt')) is not int or not 1 <= prior['attempt'] <= 99999):
        return False
    label = f"{row['source_line']:09d}_{prior['attempt']:05d}"
    if record_path.name != label + '.json' or set(prior.get('children', {})) != {'exiftool', 'ffprobe'}:
        return False
    expected_commands = commands(tools, Path(row['path']), prior['signature_candidate'])
    for name, expected in expected_commands.items():
        child_result = prior['children'][name]
        if (not isinstance(child_result, dict) or child_result.get('label') != name or
                child_result.get('state') != 'probe_ok' or child_result.get('argv') != expected or
                child_result.get('exit_code') != 0 or child_result.get('stop_reason') is not None or
                child_result.get('capture_errors') != [] or child_result.get('json_error') is not None or
                child_result.get('stderr_utf8') != '' or not usable_json(name, child_result.get('parsed'), row['path'], gate)):
            return False
        captures = child_result.get('capture')
        if not isinstance(captures, dict) or set(captures) != {'stdout', 'stderr'}:
            return False
        for stream_name, captured in captures.items():
            path = c.state_dir / 'attempts' / label / name / (stream_name + '.bin')
            if not isinstance(captured, dict) or captured.get('path') != str(path) or captured.get('truncated') is not False:
                return False
            current = file_record(path, gate, c.hash_seconds, c.stdout_bytes if stream_name == 'stdout' else c.stderr_bytes)
            if (current != captured.get('retained_record') or current['size'] != captured.get('retained_bytes') or
                    current['size'] != captured.get('stream_bytes') or current['sha256'] != captured.get('stream_sha256')):
                return False
            if stream_name == 'stderr' and current['size'] != 0:
                return False
            if stream_name == 'stdout':
                with gate.protected_file(path) as stream:
                    if strict_json(stream.read(c.stdout_bytes + 1)) != child_result['parsed']:
                        return False
    return True


def locked_tools(c, gate, locks):
    manifest, record = json_file(c.tools_manifest, gate)
    if (record['sha256'] != c.tools_sha256.lower() or set(manifest) != {'schema_version', 'tools'} or
            type(manifest['schema_version']) is not int or manifest['schema_version'] != 1):
        raise ProbeError('Approved media-tool manifest mismatch')
    if set(manifest['tools']) != {'ffprobe', 'exiftool'}:
        raise ProbeError('Exact ffprobe and ExifTool groups required')
    commands, records, roots = {}, [], []
    for name, group in manifest['tools'].items():
        root = local_path(group['root'], gate)
        if inside(c.state_dir, root) or inside(root, c.state_dir):
            raise ProbeError('State overlaps tool root')
        roots.append(root)
        if set(group) != {'root', 'executable', 'files', 'version'} or group['executable'] not in group['files']:
            raise ProbeError('Malformed approved tool group')
        if not isinstance(group['version'], str) or not 1 <= len(group['version']) <= 4096:
            raise ProbeError('Recorded tool version is missing or excessive')
        actual = set()
        pending = [root]
        while pending:
            folder = pending.pop()
            local_path(folder, gate)
            for entry in folder.iterdir():
                if entry.is_symlink() or getattr(entry.stat(follow_symlinks=False), 'st_file_attributes', 0) & 0x400:
                    raise ProbeError('Tool tree contains an aliased entry')
                if entry.is_dir() and name == 'exiftool':
                    pending.append(entry)
                elif entry.is_file() and (name == 'exiftool' or entry.name == group['executable'] or entry.suffix.lower() == '.dll'):
                    actual.add(entry.relative_to(root).as_posix())
        if actual != set(group['files']):
            raise ProbeError('Tool dependency set differs from approved manifest')
        if not 1 <= len(group['files']) <= 2000:
            raise ProbeError('Tool dependency count outside reviewed bound')
        for relative, expected in group['files'].items():
            part = Path(relative)
            if part.is_absolute() or '..' in part.parts or ':' in relative or not re.fullmatch('[a-f0-9]{64}', expected):
                raise ProbeError('Invalid approved tool dependency path/hash')
            path = root / part
            regular(path, gate)
            handle = locks.enter_context(gate.protected_file(path))
            info = hash_stream(handle, gate, c.hash_seconds, 512 * MIB)
            if info['sha256'] != expected:
                raise ProbeError('Approved tool dependency changed')
            records.append({'path': str(path), **info})
        commands[name] = [str(root / group['executable'])]
    return commands, roots, {'manifest': record, 'files': records}


def state_usage(root, gate):
    total = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        local_path(directory, gate)
        for path in directory.iterdir():
            info = path.stat(follow_symlinks=False)
            if getattr(info, 'st_file_attributes', 0) & 0x400 or stat.S_ISLNK(info.st_mode):
                raise ProbeError('Aliased state entry refused')
            if stat.S_ISDIR(info.st_mode):
                pending.append(path)
            else:
                regular(path, gate)
                total += info.st_size
    return total


def run(c, _already_locked=False):
    if os.name != 'nt':
        raise ProbeError('Production worker requires Windows suspended-child/job containment')
    for key in ('batch', 'tools_manifest', 'gate_module', 'state_dir'):
        setattr(c, key, Path(os.path.abspath(getattr(c, key))))
    for value in (c.hash_seconds, c.child_seconds, c.total_seconds):
        if not math.isfinite(value) or value <= 0:
            raise ProbeError('Time budgets must be finite and positive')
    if not (0 < c.max_file_bytes <= 128 * GIB and 128 * MIB <= c.memory_bytes <= 2 * GIB and
            0 < c.stdout_bytes <= 4 * MIB and 0 < c.stderr_bytes <= MIB and
            c.max_state_bytes >= 8 * MIB and c.reserve_bytes >= 0):
        raise ProbeError('Budgets outside bounded reviewed ranges')
    gate = load_gate(c)
    for path in (c.batch, c.tools_manifest, c.gate_module, c.state_dir):
        local_path(path, gate)
    if not c.state_dir.parent.is_dir():
        raise ProbeError('State parent must already exist')
    if c.resume and not c.dry_run and not _already_locked:
        previous, _ = json_file(c.state_dir / 'inputs.json', gate)
        if (previous.get('state_dir') != str(c.state_dir) or
                previous.get('provenance', {}).get('batch', {}).get('path') != str(c.batch)):
            raise ProbeError('Resume arguments do not identify this state/batch pair')
        state_usage(c.state_dir, gate)
        with gate.protected_file(c.state_dir / 'run.lock', writable=True):
            gate.safe_mutable_file(c.state_dir / 'status.json')
            gate.atomic_json(c.state_dir / 'status.json', {'schema_version': 1, 'phase': 'validating_resume',
                                                         'analysis_complete': False, 'updated_utc': gate.utc_now()})
            try:
                return run(c, _already_locked=True)
            except BaseException as error:
                gate.atomic_json(c.state_dir / 'status.json', {'schema_version': 1, 'phase': 'failed',
                    'analysis_complete': False, 'error': type(error).__name__ + ': ' + str(error),
                    'updated_utc': gate.utc_now()})
                raise
    with contextlib.ExitStack() as locks:
        for path in (c.batch, c.tools_manifest, c.gate_module):
            regular(path, gate)
            locks.enter_context(gate.protected_file(path))
        rows, provenance = bind_source(c, gate, locks)
        tools, tool_roots, tool_provenance = locked_tools(c, gate, locks)
        inputs = {'schema_version': 1, 'script_sha256': digest(Path(__file__).read_bytes()),
                  'provenance': provenance, 'tools': tool_provenance, 'gate_sha256': GATE_SHA256,
                  'state_dir': str(c.state_dir), 'formats': list(DEMUXERS),
                  'probe_limits': {key: getattr(c, key) for key in ('max_file_bytes', 'hash_seconds', 'child_seconds',
                                                                 'memory_bytes', 'stdout_bytes', 'stderr_bytes')},
                  'command_policy': commands(tools, Path('ARTIFACT'), 'mov')}
        if c.dry_run:
            return {'phase': 'dry_run', 'selected_files': len(rows), 'artifact_reads': False, 'writes_performed': False}
        if c.resume:
            previous, _ = json_file(c.state_dir / 'inputs.json', gate)
            if previous.get('state_dir') != str(c.state_dir):
                raise ProbeError('State ownership mismatch')
            state_usage(c.state_dir, gate)
            regular(c.state_dir / 'run.lock', gate)
        else:
            if c.state_dir.exists():
                raise ProbeError('Fresh worker requires an absent state directory')
            c.state_dir.mkdir()
            (c.state_dir / 'run.lock').touch(exist_ok=False)
            (c.state_dir / 'records').mkdir()
            (c.state_dir / 'attempts').mkdir()
        if not _already_locked:
            locks.enter_context(gate.protected_file(c.state_dir / 'run.lock', writable=True))
        status = {'schema_version': 1, 'phase': 'validating', 'analysis_complete': False,
                  'selected_files': len(rows), 'limitations': LIMITATIONS}
        def save(**values):
            status.update(values, updated_utc=gate.utc_now())
            gate.safe_mutable_file(c.state_dir / 'status.json')
            gate.atomic_json(c.state_dir / 'status.json', status)
        def event(name, **values):
            gate.safe_mutable_file(c.state_dir / 'events.jsonl')
            with (c.state_dir / 'events.jsonl').open('a', encoding='utf-8') as stream:
                stream.write(json.dumps({'utc': gate.utc_now(), 'event': name, **values}) + '\n')
                stream.flush()
                os.fsync(stream.fileno())
        save(phase='validating_resume' if c.resume else 'validating')
        try:
            if c.resume and previous != inputs:
                raise ProbeError('Resume batch/source/tool/policy identities differ')
            if not c.resume:
                gate.atomic_json(c.state_dir / 'inputs.json', inputs)
            index_path = c.state_dir / 'records-index.json'
            record_index = {}
            if index_path.exists():
                record_index, _ = json_file(index_path, gate, 64 * MIB)
                if (not isinstance(record_index, dict) or any(not re.fullmatch(r'[0-9]{9}_[0-9]{5}\.json', key)
                                                            for key in record_index)):
                    raise ProbeError('Malformed durable per-file record index')
            event('attempt_started', resume=c.resume, budgets={key: getattr(c, key) for key in
                  ('max_file_bytes', 'hash_seconds', 'child_seconds', 'total_seconds', 'memory_bytes',
                   'stdout_bytes', 'stderr_bytes', 'max_state_bytes', 'reserve_bytes')})
            started, counts = time.monotonic(), {}
            for row in rows:
                if time.monotonic() - started > c.total_seconds:
                    raise BudgetStop('Batch runtime stop threshold')
                if state_usage(c.state_dir, gate) + 4 * MIB + 2 * (c.stdout_bytes + c.stderr_bytes) > c.max_state_bytes:
                    raise BudgetStop('State byte budget')
                if shutil.disk_usage(c.state_dir).free < c.reserve_bytes + 4 * MIB + 2 * (c.stdout_bytes + c.stderr_bytes):
                    raise BudgetStop('Free-space reserve')
                number = row['source_line']
                save(phase='processing', active_source_line=number)
                old = sorted((c.state_dir / 'records').glob(f'{number:09d}_*.json'))
                if any(not re.fullmatch(r'[0-9]{9}_[0-9]{5}\.json', path.name) for path in old):
                    raise ProbeError('Invalid owned record name')
                previous_attempts = [int(path.stem.split('_')[1]) for path in old]
                previous_attempts += [int(Path(name).stem.split('_')[1]) for name in record_index
                                      if name.startswith(f'{number:09d}_')]
                for path in (c.state_dir / 'attempts').glob(f'{number:09d}_*'):
                    if not re.fullmatch(r'[0-9]{9}_[0-9]{5}', path.name):
                        raise ProbeError('Invalid owned attempt directory name')
                    previous_attempts.append(int(path.name.split('_')[1]))
                attempt = max(previous_attempts, default=0) + 1
                if attempt > 99999:
                    raise BudgetStop('Per-file attempt count exhausted')
                label = f'{number:09d}_{attempt:05d}'
                result = {'schema_version': 1, 'source': row, 'started_utc': gate.utc_now(),
                          'attempt': attempt, 'state': 'processing', 'children': {}, 'limitations': LIMITATIONS}
                path = Path(row['path'])
                try:
                    before = regular(path, gate)
                    if before != row['metadata']:
                        raise ProbeError('Recovered artifact identity/metadata differs from producer')
                    with gate.protected_file(path) as artifact:
                        full = hash_stream(artifact, gate, c.hash_seconds, c.max_file_bytes)
                        if full['sha256'] != row['sha256']:
                            raise ProbeError('Recovered artifact SHA256 differs from producer/batch')
                        result['verified_file'] = full
                        artifact.seek(0)
                        header = artifact.read(HEADER_BYTES)
                        header_record = {'policy': SIGNATURE_POLICY, 'bytes': len(header), 'sha256': digest(header)}
                        demuxer = signature(header)
                        result['signature_header'] = header_record
                        result['signature_candidate'] = demuxer
                        reuse = False
                        if old and int(old[-1].stem.split('_')[1]) == max(previous_attempts, default=0):
                            try:
                                reuse = reusable_record(c, gate, old[-1], record_index, row, full, tools, header_record, demuxer)
                            except (OSError, ProbeError, ValueError, TypeError, KeyError) as error:
                                event('previous_record_not_reusable', source_line=number, record=str(old[-1]),
                                      error=type(error).__name__ + ': ' + str(error))
                        if reuse:
                            counts['probe_ok'] = counts.get('probe_ok', 0) + 1
                            event('verified_result_reused', source_line=number, record=str(old[-1]))
                            continue
                        if demuxer is None:
                            result['state'] = 'deferred_unsupported_signature'
                        else:
                            run_dir = c.state_dir / 'attempts' / label
                            run_dir.mkdir()
                            for tool, argv in commands(tools, path, demuxer).items():
                                event('command_started', source_line=number, attempt=attempt, tool=tool, argv=argv)
                                result['children'][tool] = child(c, gate, tool, argv, run_dir / tool, tool_roots)
                            result['state'] = ('probe_ok' if all(r['state'] == 'probe_ok' for r in result['children'].values())
                                               else 'probe_incomplete')
                        after = hash_stream(artifact, gate, c.hash_seconds, c.max_file_bytes)
                        if after != full or regular(path, gate) != before:
                            raise ProbeError('Recovered artifact changed during probing')
                except BudgetStop as error:
                    result.update(state='deferred_resource', error=str(error))
                except (OSError, ProbeError) as error:
                    result.update(state='probe_incomplete', error=type(error).__name__ + ': ' + str(error))
                result['ended_utc'] = gate.utc_now()
                destination = c.state_dir / 'records' / (label + '.json')
                gate.safe_mutable_file(destination)
                if destination.exists():
                    raise ProbeError('Refusing to overwrite an earlier per-file attempt')
                gate.atomic_json(destination, result)
                record_index[destination.name] = file_record(destination, gate, c.hash_seconds, 64 * MIB)
                gate.safe_mutable_file(index_path)
                gate.atomic_json(index_path, record_index)
                counts[result['state']] = counts.get(result['state'], 0) + 1
                event('file_finished', source_line=number, attempt=attempt, state=result['state'], record=str(destination))
            for record in [provenance['batch'], provenance['source_exit'], *provenance['source_files'].values(),
                           tool_provenance['manifest'], *tool_provenance['files']]:
                if file_record(Path(record['path']), gate, c.hash_seconds, 1024 * MIB) != record:
                    raise ProbeError('Bound provenance/tool changed during processing')
            complete = counts.get('probe_ok', 0) == len(rows)
            save(phase='complete' if complete else 'complete_with_gaps', counts=counts, analysis_complete=complete,
                 completed_utc=gate.utc_now(), active_source_line=None)
            return status
        except BaseException as error:
            save(phase='deferred' if isinstance(error, BudgetStop) else 'failed', analysis_complete=False,
                 error=type(error).__name__ + ': ' + str(error))
            event('attempt_stopped', error=status['error'])
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('batch', 'tools-manifest', 'gate-module', 'state-dir'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--batch-sha256', required=True)
    parser.add_argument('--tools-sha256', required=True)
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--max-file-gib', type=int, default=16)
    parser.add_argument('--hash-seconds', type=float, default=1800)
    parser.add_argument('--child-seconds', type=float, default=60)
    parser.add_argument('--total-seconds', type=float, default=21600)
    parser.add_argument('--memory-mib', type=int, default=512)
    parser.add_argument('--max-state-mib', type=int, default=512)
    args = vars(parser.parse_args())
    args['max_file_bytes'] = args.pop('max_file_gib') * GIB
    args['memory_bytes'] = args.pop('memory_mib') * MIB
    args['max_state_bytes'] = args.pop('max_state_mib') * MIB
    try:
        result = run(Config(**args))
        print(json.dumps(result, indent=2))
        return 0 if result['phase'] in ('complete', 'dry_run') else 2
    except BaseException as error:
        print(json.dumps({'phase': 'failed', 'error': type(error).__name__ + ': ' + str(error)}), file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 1


if __name__ == '__main__':
    raise SystemExit(main())
