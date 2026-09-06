#!/usr/bin/env python3
"""Supervise one fresh NTFS free-space PhotoRec 7.2 scan; Python 3.10+, Windows.

Authored 2026-09-06. Case-local, pending independent review before evidence use.
Reads only an explicitly verified working raw image, never mounts or repairs it.
No automatic resume. Retains incomplete outputs. Limits are polled stop thresholds,
not hard quotas. Carved extensions and PhotoRec validation do not prove authenticity.
"""
from __future__ import annotations

import argparse
import codecs
import contextlib
import ctypes
from dataclasses import dataclass, asdict
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET

GIB = 1024 ** 3
MIB = 1024 ** 2
GATE_SHA256 = '5b8089929c4586c68403b5d0c37b6b88d6b632b1097e1e7a7f68d1d99e348a5e'
TOOLS_SHA256 = 'ff8d1636de929278a95da4738084ffeb91e901b31e92762641abe780a77e3179'
LIMITATIONS = [
    'Dovecot carving is disabled because its zero signature caused false positives and truncated valid WAVs in 7.2 fixtures.',
    'Only the explicit primary MBR NTFS partition free space is scanned; no allocated/slack/gap/other-partition carving.',
    'Stop thresholds are polled; output/log/space limits can overshoot between checks and during directory enumeration.',
    'Carved names and extraction times do not establish original path, deletion date, owner, contact, or media authenticity.',
    'PhotoRec-generated thumbnails may have no XML source mapping; they remain explicitly unverified for allocation provenance.',
    'Current allocation bitmap cannot establish historical allocation or prove recovered bytes are original deleted content.',
    'No automatic resume; a stopped scan requires a separately scoped subsequent action.',
]


class CarveError(RuntimeError):
    pass


class ThresholdStop(CarveError):
    pass


@dataclass
class Config:
    image: Path
    preservation_state: Path
    preservation_exit_code: Path
    gate_module: Path
    approved_tools: Path
    photorec_dir: Path
    tsk_bin: Path
    state_dir: Path
    output_dir: Path
    partition_number: int
    partition_offset: int
    partition_length: int
    sector_size: int
    max_output_bytes: int
    max_files: int = 100000
    max_log_bytes: int = 256 * MIB
    max_seconds: float = 24 * 3600
    poll_seconds: float = 1.0
    reserve_bytes: int = 64 * GIB
    cushion_bytes: int = 2 * GIB


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(MIB), b''):
            h.update(block)
    return h.hexdigest()


def absolute(path):
    return Path(os.path.abspath(path))


def same(a, b):
    return os.path.normcase(str(absolute(a))) == os.path.normcase(str(absolute(b)))


def inside(path, root):
    return path == root or root in path.parents


def entries_in(path):
    # Close the Windows directory handle before processing entries/raising stops.
    with os.scandir(path) as iterator:
        return list(iterator)


def reject_reparse(info):
    if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise CarveError('Symlink/reparse point appeared inside owned output/state')


def checked_directory(path, gate):
    info = path.stat(follow_symlinks=False)
    reject_reparse(info)
    if not stat.S_ISDIR(info.st_mode):
        raise CarveError('Owned traversal directory changed type')
    gate.require_unaliased(path)


def load_gate(path):
    path = absolute(path)
    if not same(path.resolve(), path) or path.is_symlink():
        raise CarveError('Approved inventory gate path/hash mismatch')
    source = path.read_bytes()
    if hashlib.sha256(source).hexdigest() != GATE_SHA256:
        raise CarveError('Approved inventory gate path/hash mismatch')
    spec = importlib.util.spec_from_file_location('photorec_pinned_inventory_gate', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    # Execute exactly the bytes just hashed; do not create/replace gate bytecode.
    exec(compile(source, str(path), 'exec'), module.__dict__)
    return module


def normalize(c, gate):
    for name in ('image', 'preservation_state', 'preservation_exit_code', 'gate_module',
                 'approved_tools', 'photorec_dir', 'tsk_bin', 'state_dir', 'output_dir'):
        setattr(c, name, absolute(getattr(c, name)))
    if (type(c.partition_number) is not int or not 1 <= c.partition_number <= 4 or
            c.sector_size != 512 or type(c.partition_offset) is not int or c.partition_offset < 1 or
            type(c.partition_length) is not int or c.partition_length <= 1):
        raise CarveError('Only explicit primary MBR partitions and 512-byte sectors are supported')
    if re.search(r'\.\d+$', c.image.name):
        raise CarveError('Numbered image segments are refused to prevent implicit sibling reads')
    if c.image.suffix.lower() != '.raw':
        raise CarveError('Working image must have an explicit .raw suffix')
    for name in ('max_output_bytes', 'max_files', 'max_log_bytes'):
        if type(getattr(c, name)) is not int or getattr(c, name) <= 0:
            raise CarveError(f'{name} must be a positive integer')
    if c.max_files > 1000000 or c.max_log_bytes > GIB:
        raise CarveError('File/log limits exceed supported bounded validation size')
    for value in (c.max_seconds, c.poll_seconds):
        if not math.isfinite(value) or value <= 0:
            raise CarveError('Runtime and poll interval must be finite and positive')
    if c.max_seconds > 7 * 24 * 3600 or c.poll_seconds > 5:
        raise CarveError('Runtime must be <= 7 days and poll interval <= 5 seconds')
    if c.reserve_bytes < 0 or c.cushion_bytes < 0:
        raise CarveError('Negative reserve/cushion refused')
    # Image parent only: never stat/open a partial working image before its gate.
    for path in (c.image.parent, c.preservation_state, c.preservation_exit_code,
                 c.gate_module, c.approved_tools, c.photorec_dir, c.tsk_bin, c.state_dir, c.output_dir):
        gate.require_unaliased(path)
    inputs = (c.image, c.preservation_state, c.preservation_exit_code, c.gate_module.parent,
              c.approved_tools, c.photorec_dir, c.tsk_bin)
    for target in (c.state_dir, c.output_dir):
        if not target.parent.is_dir() or target.exists() or target.is_symlink():
            raise CarveError('Each output/state root must be fresh with an existing parent')
        for source in inputs:
            if inside(target, source) or inside(source, target):
                raise CarveError('Output/state roots may not overlap inputs, preservation, or tools')
    if inside(c.state_dir, c.output_dir) or inside(c.output_dir, c.state_dir):
        raise CarveError('State/output roots must be disjoint')


@contextlib.contextmanager
def locked_tools(c, gate):
    """Pin all staged DLLs plus the selected executables and keep read locks."""
    with contextlib.ExitStack() as stack:
        for path in (c.gate_module, c.approved_tools):
            gate.require_unaliased(path)
            stack.enter_context(gate.protected_file(path))
        if sha(c.gate_module) != GATE_SHA256 or sha(c.approved_tools) != TOOLS_SHA256:
            raise CarveError('Pinned gate/tool-manifest hash changed')
        manifest = gate.read_json(c.approved_tools)
        records = []
        for group, folder in (('photorec', c.photorec_dir), ('tsk', c.tsk_bin)):
            entries = manifest['files'][group]
            actual_dlls = {p.name for p in folder.iterdir() if p.suffix.lower() == '.dll'}
            if actual_dlls != {name for name in entries if name.lower().endswith('.dll')}:
                raise CarveError('Staged DLL set differs from approved tool manifest')
            for name, expected in entries.items():
                if Path(name).name != name or ':' in name:
                    raise CarveError('Invalid approved tool name')
                path = folder / name
                gate.require_unaliased(path)
                stream = stack.enter_context(gate.protected_file(path))
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or sha(path) != expected:
                    raise CarveError(f'Approved tool hash mismatch: {name}')
                records.append({'path': str(path), 'sha256': expected, 'metadata': gate.metadata(info)})
        yield {'photorec': [str(c.photorec_dir / 'photorec_win.exe')],
               'istat': [str(c.tsk_bin / 'istat.exe')], 'icat': [str(c.tsk_bin / 'icat.exe')],
               'fsstat': [str(c.tsk_bin / 'fsstat.exe')],
               'records': records}
        for record in records:
            if gate.metadata(Path(record['path']).stat()) != record['metadata']:
                raise CarveError('Tool metadata changed during protected use')


def geometry(stream, c, image_size):
    stream.seek(0)
    mbr = stream.read(512)
    if len(mbr) != 512 or mbr[510:512] != b'\x55\xaa':
        raise CarveError('Invalid MBR signature')
    entries = []
    for number in range(1, 5):
        entry = mbr[446 + (number - 1) * 16:462 + (number - 1) * 16]
        entries.append({'number': number, 'active': entry[0], 'type': entry[4],
                        'offset': struct.unpack_from('<I', entry, 8)[0],
                        'length': struct.unpack_from('<I', entry, 12)[0]})
    if any(e['type'] == 0xee for e in entries):
        raise CarveError('GPT/protective MBR not supported by this supervisor')
    selected = entries[c.partition_number - 1]
    if (selected['type'] != 7 or selected['active'] not in (0, 128) or
            selected['offset'] != c.partition_offset or selected['length'] != c.partition_length):
        raise CarveError('Explicit partition differs from primary MBR type/offset/length')
    start = c.partition_offset * c.sector_size
    length = c.partition_length * c.sector_size
    if start + length > image_size:
        raise CarveError('Partition exceeds the verified image')
    for other in entries:
        if other is not selected and other['length'] and other['type']:
            if max(selected['offset'], other['offset']) < min(selected['offset'] + selected['length'], other['offset'] + other['length']):
                raise CarveError('Selected partition overlaps another MBR entry')
    stream.seek(start)
    boot = stream.read(512)
    if len(boot) != 512 or boot[3:11] != b'NTFS    ' or boot[510:512] != b'\x55\xaa':
        raise CarveError('Selected partition has no recognized NTFS boot sector')
    bps = struct.unpack_from('<H', boot, 11)[0]
    spc = boot[13]
    sectors = struct.unpack_from('<Q', boot, 40)[0]
    if (bps != c.sector_size or spc not in (1, 2, 4, 8, 16, 32, 64, 128) or
            any(boot[14:21]) or any(boot[22:24]) or any(boot[32:36]) or sectors <= 0):
        raise CarveError('Unsupported/invalid NTFS boot geometry')
    if sectors + 1 != c.partition_length:
        raise CarveError('NTFS/MBR length is incompatible with strict PhotoRec 7.2 scope; no repair/fallback')
    clusters = sectors // spc
    minimum_bitmap = (clusters + 7) // 8
    if not clusters or minimum_bitmap > 128 * MIB:
        raise CarveError('Unsupported NTFS allocation bitmap size')
    return {'mbr_entries': entries, 'partition_number': c.partition_number,
            'partition_offset_sectors': c.partition_offset, 'partition_length_sectors': c.partition_length,
            'partition_start': start, 'partition_bytes': length, 'sector_size': bps,
            'cluster_size': bps * spc, 'ntfs_sectors': sectors, 'clusters': clusters,
            'minimum_bitmap_bytes': minimum_bitmap,
            'mbr_sha256': hashlib.sha256(mbr).hexdigest(), 'boot_sha256': hashlib.sha256(boot).hexdigest()}


def check_fsstat(text, geo):
    expected = [('File System Type', 'NTFS'), ('Sector Size', str(geo['sector_size'])),
                ('Cluster Size', str(geo['cluster_size'])), ('Total Cluster Range', f"0 - {geo['clusters'] - 1}"),
                ('Total Sector Range', f"0 - {geo['ntfs_sectors'] - 1}")]
    for field, value in expected:
        if re.findall(r'^' + re.escape(field) + r':\s*([^\r\n]+)', text, re.M) != [value]:
            raise CarveError('TSK filesystem geometry does not corroborate the explicit NTFS boot geometry')


class Recorder:
    def __init__(self, c, gate):
        self.c, self.gate = c, gate
        self.started = time.monotonic()
        self.last_update = 0.0
        self.last_guard = 0.0
        self.stop_reason = None
        self.status = {'schema_version': 1, 'phase': 'running', 'scan_completed': False,
                       'supervisor_pid': os.getpid(),
                       'started_utc': gate.utc_now(), 'limitations': LIMITATIONS,
                       'configuration': {k: str(v) if isinstance(v, Path) else v for k, v in asdict(c).items()}}
        self.save()

    def write_json(self, name, value):
        path = self.c.state_dir / name
        self.gate.safe_mutable_file(path)
        self.gate.atomic_json(path, value)

    def save(self, **fields):
        self.status.update(fields)
        self.status['updated_utc'] = self.gate.utc_now()
        self.write_json('status.json', self.status)
        self.last_update = time.monotonic()

    def event(self, kind, **fields):
        path = self.c.state_dir / 'events.jsonl'
        self.gate.safe_mutable_file(path)
        with path.open('a', encoding='utf-8', newline='\n') as out:
            out.write(json.dumps({'utc': self.gate.utc_now(), 'event': kind, **fields}, ensure_ascii=True) + '\n')
            out.flush()

    def check(self, force_status=False):
        if self.stop_reason:
            raise ThresholdStop(self.stop_reason)
        if time.monotonic() - self.started >= self.c.max_seconds:
            raise ThresholdStop('runtime_stop_threshold')
        now = time.monotonic()
        if not force_status and now - self.last_guard < self.c.poll_seconds:
            return
        self.last_guard = now
        free = min(shutil.disk_usage(self.c.output_dir).free, shutil.disk_usage(self.c.state_dir).free)
        if free <= self.c.reserve_bytes + self.c.cushion_bytes:
            raise ThresholdStop('free_space_reserve_plus_write_cushion')
        total = count = log_bytes = 0
        began = time.monotonic()
        for root in (self.c.output_dir, self.c.state_dir):
            pending = [root]
            while pending:
                directory = pending.pop()
                checked_directory(directory, self.gate)
                for entry in entries_in(directory):
                    path = Path(entry.path)
                    if time.monotonic() - began > 5:
                        raise ThresholdStop('directory_monitor_exceeded_five_seconds')
                    # Windows DirEntry.stat can leave inode/link fields zero.
                    # Scandir supplies a direct child name of a freshly canonical
                    # directory; fresh lstat rejects leaf aliases without resolving
                    # every ordinary leaf's full ancestor chain again.
                    info = path.stat(follow_symlinks=False)
                    reject_reparse(info)
                    if stat.S_ISDIR(info.st_mode):
                        self.gate.require_unaliased(path)
                        pending.append(path)
                    elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                        if root == self.c.output_dir:
                            total += info.st_size
                            if path.name != 'report.xml':
                                count += 1
                        if path.suffix == '.log' or path.name in ('report.xml', 'photorec.ses', 'events.jsonl'):
                            log_bytes += info.st_size
                    else:
                        raise CarveError('Nonregular/hardlinked output or state file detected')
                    if total >= self.c.max_output_bytes or count > self.c.max_files:
                        raise ThresholdStop('retained_output_bytes_or_file_count_stop_threshold')
                    if log_bytes >= self.c.max_log_bytes:
                        raise ThresholdStop('log_report_session_stop_threshold')
        if force_status or time.monotonic() - self.last_update >= 5:
            self.save(output_bytes_observed=total, output_files_observed=count,
                      log_bytes_observed=log_bytes, free_bytes_observed=free,
                      monitor_seconds=time.monotonic() - began)
        self.last_guard = time.monotonic()


class WindowsJob:
    """Kill the native process if this supervisor exits or is terminated."""
    def __init__(self):
        self.handle = None
        if os.name != 'nt':
            return
        from ctypes import wintypes as w
        class Basic(ctypes.Structure):
            _fields_ = [('process_time', ctypes.c_int64), ('job_time', ctypes.c_int64),
                        ('flags', w.DWORD), ('min_working', ctypes.c_size_t), ('max_working', ctypes.c_size_t),
                        ('active_limit', w.DWORD), ('affinity', ctypes.c_size_t), ('priority', w.DWORD), ('scheduling', w.DWORD)]
        class IO(ctypes.Structure):
            _fields_ = [(n, ctypes.c_uint64) for n in ('read_ops', 'write_ops', 'other_ops', 'read_bytes', 'write_bytes', 'other_bytes')]
        class Extended(ctypes.Structure):
            _fields_ = [('basic', Basic), ('io', IO), ('process_memory', ctypes.c_size_t),
                        ('job_memory', ctypes.c_size_t), ('peak_process', ctypes.c_size_t), ('peak_job', ctypes.c_size_t)]
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, w.LPCWSTR]
        self.kernel.CreateJobObjectW.restype = w.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
        self.kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        self.kernel.CloseHandle.argtypes = [w.HANDLE]
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = Extended()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise ctypes.WinError(ctypes.get_last_error())

    def assign(self, process):
        if self.handle and not self.kernel.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def child_environment(c):
    env = os.environ.copy()
    # Child-only locations prevent PhotoRec loading/saving an analyst's preferences.
    for key in ('HOME', 'USERPROFILE', 'HOMEPATH', 'TMP', 'TEMP'):
        env[key] = str(c.state_dir / 'cwd')
    env['__COMPAT_LAYER'] = 'RunAsInvoker'
    env['TZ'] = 'UTC'
    env['PATH'] = os.pathsep.join([str(c.photorec_dir), str(c.tsk_bin),
                                str(Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32')])
    return env


def run_child(c, rec, label, argv, stdout_limit=MIB, truncate_stdout=False):
    stdout_path, stderr_path = c.state_dir / f'{label}.stdout.log', c.state_dir / f'{label}.stderr.log'
    rec.event('command_started', label=label, argv=argv)
    rec.check()
    results = {}
    def pump(pipe, path, limit, allow_truncation, name):
        h, count, written = hashlib.sha256(), 0, 0
        try:
            with path.open('xb') as sink:
                for data in iter(lambda: pipe.read(65536), b''):
                    h.update(data)
                    count += len(data)
                    kept = data[:max(0, limit - written)]
                    sink.write(kept)
                    written += len(kept)
                    if count > limit and not allow_truncation:
                        rec.stop_reason = f'{label}_{name}_capture_limit'
                sink.flush()
        except BaseException as error:
            rec.stop_reason = f'{label}_{name}_capture_failed: {type(error).__name__}'
        finally:
            pipe.close()
            results[name] = {'path': str(path), 'stream_bytes': count, 'retained_bytes': written,
                             'stream_sha256': h.hexdigest(), 'truncated': count > written}
    job = WindowsJob()
    process = None
    threads = []
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   cwd=c.state_dir / 'cwd', env=child_environment(c), shell=False,
                                   creationflags=0x08000000 if os.name == 'nt' else 0)
        job.assign(process)
        rec.save(stage=label, active_child_pid=process.pid)
        for name, path, pipe, limit, trunc in [('stdout', stdout_path, process.stdout, stdout_limit, truncate_stdout),
                                              ('stderr', stderr_path, process.stderr, MIB, False)]:
            thread = threading.Thread(target=pump, args=(pipe, path, limit, trunc, name), daemon=True)
            thread.start()
            threads.append(thread)
        while process.poll() is None:
            rec.check()
            if label == 'photorec':
                check_log_errors(c.state_dir / 'photorec.log', partial=True)
            time.sleep(c.poll_seconds)
        for thread in threads:
            thread.join(timeout=5)
        if any(t.is_alive() for t in threads):
            raise CarveError('Native output readers did not close')
        rec.check(force_status=True)
        record = {'argv': argv, 'exit_code': process.returncode, 'streams': results}
        rec.write_json(f'{label}.command.json', record)
        rec.event('command_finished', label=label, exit_code=process.returncode)
        if process.returncode != 0 or results.get('stderr', {}).get('stream_bytes', 1):
            raise CarveError(f'{label} failed or wrote stderr; retained logs describe the error')
        return stdout_path
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        job.close()
        for thread in threads:
            thread.join(timeout=5)
        if process is not None:
            rec.write_json(f'{label}.exit.json', {'exit_code': process.returncode, 'streams': results,
                           'stop_reason': rec.stop_reason, 'utc': rec.gate.utc_now()})
            rec.save(active_child_pid=None)


def bitmap_attribute(text, geo):
    if not re.search(r'^Allocated File\s*$', text, re.M) or not re.search(r'^Name: \$Bitmap\s*$', text, re.M):
        raise CarveError('TSK record 6 is not an allocated $Bitmap')
    rows = re.findall(r'^Type: \$DATA \(128-(\d+)\)[ \t]+Name: N/A[ \t]+(Non-Resident|Resident)[ \t]+size: (\d+)(?:[ \t]+init_size: (\d+))?[ \t]*\r?$', text, re.M)
    if len(rows) != 1:
        raise CarveError('Exactly one explicit unnamed $Bitmap DATA attribute is required')
    attribute, storage, length, initialized = rows[0]
    if storage == 'Non-Resident' and not initialized:
        raise CarveError('Non-resident NTFS bitmap requires an explicit initialized size')
    length = int(length)
    minimum = geo['minimum_bitmap_bytes']
    if not minimum <= length <= (minimum + 7) // 8 * 8 or (initialized and int(initialized) != length):
        raise CarveError('NTFS bitmap length/initialized size is inconsistent with cluster geometry')
    return f'6-128-{int(attribute)}', length


def check_log_errors(path, partial=False):
    if not path.exists():
        if partial:
            return None
        raise CarveError('PhotoRec log missing')
    # Tail suffices for prompt interruption; full log is examined after native exit.
    with path.open('rb') as stream:
        if partial:
            stream.seek(max(0, path.stat().st_size - 65536))
        data = stream.read(65536 if partial else GIB + 1)
    text = data.decode('utf-8', errors='replace')
    if re.search(r'(?i)\b(error|failed|cannot|damaged)\b|can.t open|couldn.t|short read|no space', text):
        raise CarveError('PhotoRec reported an error; requested free-space scope is not certified')
    if not partial:
        if 'ntfs_remove_used_space' not in text or 'PhotoRec exited normally.' not in text:
            raise CarveError('Missing NTFS bitmap-filter trace or normal completion marker')
        totals = re.findall(r'Total: (\d+) files? found', text)
        if len(totals) != 1:
            raise CarveError('Missing/ambiguous PhotoRec final file count')
        return int(totals[0])
    return None


def decimal(value, name):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{1,20}', value):
        raise CarveError(f'Invalid XML integer: {name}')
    return int(value)


def unallocated_range(start, length, geo, bitmap):
    relative = start - geo['partition_start']
    if relative < 0 or length <= 0 or relative + length > geo['clusters'] * geo['cluster_size']:
        raise CarveError('Carved physical run lies outside the NTFS bitmap-covered cluster range')
    first, last = relative // geo['cluster_size'], (relative + length - 1) // geo['cluster_size']
    byte0, bit0 = divmod(first, 8)
    byte1, bit1 = divmod(last, 8)
    if byte0 == byte1:
        used = bitmap[byte0] & (((1 << (bit1 - bit0 + 1)) - 1) << bit0)
    else:
        used = (bitmap[byte0] & (255 << bit0)) or (bitmap[byte1] & ((1 << (bit1 + 1)) - 1)) or any(bitmap[byte0 + 1:byte1])
    if used:
        raise CarveError('Carved physical run intersects an allocated NTFS cluster')


def output_path(name, report, c, gate):
    if not isinstance(name, str) or not name or any(ord(ch) < 32 for ch in name):
        raise CarveError('Invalid XML filename')
    value = Path(name)
    if '..' in value.parts:
        raise CarveError('Parent traversal in XML filename')
    path = absolute(value if value.is_absolute() else report.parent / value)
    gate.require_unaliased(path)
    if (path.parent.parent != c.output_dir or not re.fullmatch(r'recup\.[1-9][0-9]*', path.parent.name)
            or not re.fullmatch(r'[fbt][0-9]{7,}[^/\\:]*', path.name)):
        raise CarveError('XML output path is outside the exact controlled recovery directories')
    return path


def report_records(report, c, gate, geo, bitmap, image_size):
    # Explicitly reject declarations; ElementTree does not fetch external entities.
    overlap = b''
    decoder = codecs.getincrementaldecoder('utf-8')('strict')
    with report.open('rb') as stream:
        prefix = stream.read(128)
        if not re.search(br'^\s*<\?xml[^>]+encoding=[\'"]UTF-8[\'"]', prefix):
            raise CarveError('Report must declare the pinned producer UTF-8 encoding')
        stream.seek(0)
        for block in iter(lambda: stream.read(65536), b''):
            decoder.decode(block)
            data = overlap + block
            if b'\0' in data or b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
                raise CarveError('DTD/entity declarations are prohibited in PhotoRec reports')
            overlap = data[-16:]
        decoder.decode(b'', final=True)
    source_ok = creator_ok = False
    source_count = creator_count = 0
    depth = count = 0
    ancestry = []
    root_children = {'creator', 'source', 'configuration', 'fileobject',
                     '{http://www.forensicswiki.org/wiki/Category:Digital_Forensics_XML}metadata'}
    root = None
    for event, element in ET.iterparse(report, events=('start', 'end')):
        if event == 'start':
            depth += 1
            ancestry.append(element.tag)
            if depth > 32:
                raise CarveError('XML nesting exceeds supported bounds')
            if root is None:
                root = element
                if root.tag != 'dfxml':
                    raise CarveError('Unexpected PhotoRec XML root')
            if depth == 2 and element.tag not in root_children:
                raise CarveError('Unexpected or foreign-namespaced XML root child')
            local_name = element.tag.split('}')[-1]
            if local_name == 'fileobject' and ancestry != ['dfxml', 'fileobject']:
                raise CarveError('Misplaced or foreign-namespaced XML fileobject')
            if local_name == 'byte_run' and ancestry not in (
                    ['dfxml', 'source', 'volume', 'byte_runs', 'byte_run'],
                    ['dfxml', 'fileobject', 'byte_runs', 'byte_run']):
                raise CarveError('Misplaced or foreign-namespaced XML physical run')
            continue
        if depth == 2 and element.tag == 'creator':
            creator_count += 1
            if creator_count != 1 or len(element.findall('package')) != 1 or len(element.findall('version')) != 1:
                raise CarveError('Ambiguous XML producer')
            creator_ok = element.findtext('package') == 'PhotoRec' and element.findtext('version') == '7.2'
            if not creator_ok:
                raise CarveError('XML producer does not match pinned PhotoRec 7.2')
            element.clear()
        elif depth == 2 and element.tag == 'source':
            source_count += 1
            if source_count != 1 or any(len(element.findall(key)) != 1 for key in
                                       ('image_filename', 'image_size', 'sectorsize', 'volume', 'volume/block_size', 'volume/byte_runs')):
                raise CarveError('Ambiguous XML source geometry')
            source_runs = element.findall('volume/byte_runs/byte_run')
            if (not same(element.findtext('image_filename', ''), c.image) or
                    element.findtext('image_filename') != str(c.image) or
                    decimal(element.findtext('image_size'), 'image_size') != image_size or
                    decimal(element.findtext('sectorsize'), 'sectorsize') != c.sector_size or
                    decimal(element.findtext('volume/block_size'), 'block_size') != geo['cluster_size'] or len(source_runs) != 1):
                raise CarveError('XML source identity/geometry differs from explicit verified input')
            run = source_runs[0]
            if (decimal(run.get('offset'), 'offset') != 0 or decimal(run.get('img_offset'), 'img_offset') != geo['partition_start'] or
                    decimal(run.get('len'), 'len') != geo['partition_bytes']):
                raise CarveError('XML partition range differs from explicit scope')
            source_ok = True
            element.clear()
        elif depth == 2 and element.tag == 'fileobject':
            if not source_ok or not creator_ok:
                raise CarveError('XML file precedes verified source/creator')
            count += 1
            if count > c.max_files * 2:
                raise CarveError('XML fileobject count exceeds validation bound')
            if len(element.findall('filename')) != 1 or len(element.findall('filesize')) != 1:
                raise CarveError('Ambiguous XML filename/filesize')
            if len(element.findall('byte_runs')) != 1 or sorted(child.tag for child in element) != ['byte_runs', 'filename', 'filesize']:
                raise CarveError('Unexpected XML fileobject structure')
            if any(child.tag != 'byte_run' for child in element.find('byte_runs')):
                raise CarveError('Unexpected XML physical-run structure')
            path = output_path(element.findtext('filename'), report, c, gate)
            size = decimal(element.findtext('filesize'), 'filesize')
            if not size:
                raise CarveError('Unexpected zero-sized PhotoRec XML record')
            runs, coverage = [], 0
            for run in element.findall('byte_runs/byte_run'):
                if len(runs) >= 10000:
                    raise CarveError('Too many physical runs for one carved record')
                offset, start, length = (decimal(run.get(key), key) for key in ('offset', 'img_offset', 'len'))
                if offset != coverage:
                    raise CarveError('XML file offsets are not cumulative/contiguous')
                unallocated_range(start, length, geo, bitmap)
                runs.append({'file_offset': offset, 'image_offset': start, 'length': length})
                coverage += length
            if size and (coverage < size or coverage - size >= geo['cluster_size']):
                raise CarveError('XML physical coverage does not match filesize plus final cluster padding')
            yield {'path': str(path), 'reported_size': size, 'physical_runs': runs,
                   'report': str(report), 'allocation_validation': 'all_reported_physical_runs_unallocated',
                   'physical_padding_bytes': max(0, coverage - size)}
            element.clear()
        depth -= 1
        ancestry.pop()
    if not source_ok or not creator_ok:
        raise CarveError('Incomplete PhotoRec XML source/creator')


def hash_output(path, rec, gate):
    gate.safe_mutable_file(path)
    h, count, nonzero = hashlib.sha256(), 0, False
    with gate.protected_file(path) as stream:
        before = gate.metadata(os.fstat(stream.fileno()))
        last_check = time.monotonic()
        for block in iter(lambda: stream.read(MIB), b''):
            h.update(block)
            count += len(block)
            nonzero = nonzero or any(block)
            if time.monotonic() - last_check >= 1:
                rec.check()
                last_check = time.monotonic()
        if before != gate.metadata(os.fstat(stream.fileno())) or before != gate.metadata(path.stat()) or count != before['size']:
            raise CarveError('Recovered output changed during hashing')
    return {'sha256': h.hexdigest(), 'size': count, 'metadata': before, 'all_zero': not nonzero}


def validate_outputs(c, rec, gate, geo, bitmap, image_gate, native_count):
    for item in c.output_dir.iterdir():
        gate.require_unaliased(item)
        if not item.is_dir() or not re.fullmatch(r'recup\.[1-9][0-9]*', item.name):
            raise CarveError('Unexpected item at the controlled recovery root')
        for child in item.iterdir():
            gate.safe_mutable_file(child)
    reports = sorted(c.output_dir.glob('recup.*/report.xml'))
    if not reports:
        raise CarveError('PhotoRec report.xml missing')
    mapping = {}
    for report in reports:
        gate.safe_mutable_file(report)
        with gate.protected_file(report):
            for record in report_records(report, c, gate, geo, bitmap, image_gate['size']):
                key = os.path.normcase(record['path'])
                if key in mapping:
                    raise CarveError('Duplicate XML output references')
                mapping[key] = record
        rec.check()
    manifest = c.state_dir / 'output-manifest.jsonl'
    exported = thumbnails_unmapped = detections_only = 0
    with manifest.open('x', encoding='utf-8', newline='\n') as sink:
        for path in sorted(c.output_dir.glob('recup.*/*')):
            if path.name == 'report.xml':
                continue
            output_path(str(path), reports[0], c, gate)
            record = mapping.pop(os.path.normcase(str(path)), None)
            info = hash_output(path, rec, gate)
            if record is None:
                if not re.fullmatch(r't[0-9]{7,}\.jpg', path.name):
                    raise CarveError('Ordinary recovered file has no XML source mapping')
                thumbnails_unmapped += 1
                record = {'path': str(path), 'physical_runs': None, 'allocation_validation': 'unverified_thumbnail_parent',
                          'limitation': 'PhotoRec 7.2 can write thumbnails without XML entries; no parent inferred from name.'}
            elif record['reported_size'] != info['size']:
                raise CarveError('Recovered file size differs from XML report')
            if path.suffix.lower() == '.dovecot':
                raise CarveError('Dovecot output violates the explicit disabled-family configuration')
            category = {'f': 'PhotoRec_named_file', 'b': 'PhotoRec_broken_candidate', 't': 'PhotoRec_thumbnail'}[path.name[0]]
            record.update(info, classification=category, content_authenticity='not_established', image_sha256=image_gate['sha256'])
            sink.write(json.dumps(record, ensure_ascii=True) + '\n')
            if path.name[0] != 't':
                exported += 1
            rec.check()
        for record in mapping.values():
            path = Path(record['path'])
            if path.suffix.lower() in ('.ctg', '.fat', '.ext', '.hfsp', '.mft', '.dsc'):
                classification = 'PhotoRec_report_only_metadata_detection'
            else:
                raise CarveError('XML reports a missing ordinary recovered file')
            detections_only += 1
            record.update(classification=classification, image_sha256=image_gate['sha256'])
            sink.write(json.dumps(record, ensure_ascii=True) + '\n')
        sink.flush()
        os.fsync(sink.fileno())
    if exported != native_count:
        raise CarveError('Retained ordinary file count differs from PhotoRec final count')
    return {'ordinary_files': exported, 'unmapped_thumbnails': thumbnails_unmapped,
            'report_only_candidates': detections_only, 'reports': [gate.digest_file(p) for p in reports],
            'output_manifest': gate.digest_file(manifest), 'reported_allocation_extents_verified': True}


def inventory_partial(c, rec):
    """Bounded metadata-only inventory after a stop; never certify unfinished bytes."""
    began, count, truncated = time.monotonic(), 0, False
    target = c.state_dir / 'retained-outputs.partial.jsonl'
    rec.gate.safe_mutable_file(target)
    with target.open('x', encoding='utf-8', newline='\n') as sink:
        pending = [c.output_dir] if c.output_dir.exists() else []
        while pending:
            for entry in entries_in(pending.pop()):
                if time.monotonic() - began >= 10 or count >= c.max_files + 1000:
                    truncated = True
                    pending.clear()
                    break
                path = Path(entry.path)
                info = path.stat(follow_symlinks=False)
                aliased = entry.is_symlink() or not same(path.resolve(), path)
                if stat.S_ISDIR(info.st_mode) and not aliased:
                    pending.append(path)
                else:
                    count += 1
                    sink.write(json.dumps({'path': str(path), 'metadata': rec.gate.metadata(info),
                        'regular_unaliased': stat.S_ISREG(info.st_mode) and not aliased and info.st_nlink == 1,
                        'sha256': None, 'hash_status': 'deferred_after_stop',
                        'allocation_validation': 'not_certified', 'partial_output': True}, ensure_ascii=True) + '\n')
        sink.flush()
    return {'retained_metadata_inventory': str(target), 'retained_metadata_rows': count,
            'retained_metadata_inventory_truncated': truncated}


def supervise(c):
    gate = load_gate(c.gate_module)
    normalize(c, gate)
    # Pending preservation is rejected before creating state or touching the image.
    image_gate = gate.read_preservation_gate(c)
    if image_gate is None:
        raise CarveError('Preservation incomplete; no image read or carving attempted')
    c.state_dir.mkdir()
    rec = Recorder(c, gate)
    output_owned = False
    try:
        c.output_dir.mkdir()
        output_owned = True
        (c.state_dir / 'cwd').mkdir()
        rec.event('supervisor_started', python=sys.version, runner_sha256=sha(Path(__file__)))
        rec.check()
        with contextlib.ExitStack() as locks:
            locks.enter_context(gate.protected_file(Path(__file__).resolve()))
            for path in (c.preservation_state / 'manifest.json', c.preservation_state / 'status.json', c.preservation_exit_code):
                gate.require_unaliased(path)
                locks.enter_context(gate.protected_file(path))
            if gate.read_preservation_gate(c) != image_gate:
                raise CarveError('Preservation gate changed before protected use')
            tools = locks.enter_context(locked_tools(c, gate))
            gate.require_unaliased(c.image)
            image = locks.enter_context(gate.protected_file(c.image))
            gate.check_image_handle(c, image_gate, image)
            geo = geometry(image, c, image_gate['size'])
            inputs = {'image_gate': image_gate, 'geometry': geo, 'tools': tools['records'],
                      'gate_sha256': GATE_SHA256, 'approved_tools_sha256': TOOLS_SHA256,
                      'runner_sha256': sha(Path(__file__)), 'configuration': rec.status['configuration']}
            rec.write_json('inputs.json', inputs)
            common = ['-i', 'raw', '-f', 'ntfs', '-b', str(c.sector_size), '-o', str(c.partition_offset)]
            fsstat = run_child(c, rec, 'fsstat', tools['fsstat'] + common + [str(c.image)])
            check_fsstat(fsstat.read_text(encoding='utf-8'), geo)
            istat = run_child(c, rec, 'istat_bitmap', tools['istat'] + common + ['-z', 'UTC', str(c.image), '6'])
            attr, expected = bitmap_attribute(istat.read_text(encoding='utf-8'), geo)
            bitmap_path = run_child(c, rec, 'icat_bitmap', tools['icat'] + common + [str(c.image), attr], expected)
            bitmap = bitmap_path.read_bytes()
            if len(bitmap) != expected:
                raise CarveError('Independent NTFS bitmap extraction is incomplete')
            rec.write_json('bitmap.json', {'attribute': attr, 'expected_bytes': expected,
                           'artifact': gate.digest_file(bitmap_path), 'geometry': geo})
            gate.check_image_handle(c, image_gate, image)
            tail = (f'partition_i386,options,paranoid,keep_corrupted_file_no,{c.partition_number},'
                    'fileopt,everything,enable,dovecot,disable,freespace,search')
            argv = tools['photorec'] + ['/debug', '/log', '/logname', str(c.state_dir / 'photorec.log'),
                                       '/d', str(c.output_dir / 'recup'), '/cmd', str(c.image), tail]
            run_child(c, rec, 'photorec', argv, MIB, truncate_stdout=True)
            native_count = check_log_errors(c.state_dir / 'photorec.log')
            rec.save(stage='validating_outputs')
            outputs = validate_outputs(c, rec, gate, geo, bitmap, image_gate, native_count)
            rec.check(force_status=True)
            gate.check_image_handle(c, image_gate, image)
            if gate.read_preservation_gate(c) != image_gate:
                raise CarveError('Preservation gate changed before completion')
        rec.event('supervisor_complete', **outputs)
        rec.save(phase='complete', stage='complete', scan_completed=True, completed_utc=gate.utc_now(), **outputs)
        rec.write_json('supervisor-exit.json', {'exit_code': 0, 'phase': 'complete', 'utc': gate.utc_now()})
        return 0
    except BaseException as error:
        phase = 'incomplete' if isinstance(error, (ThresholdStop, KeyboardInterrupt)) else 'failed'
        message = str(error) or type(error).__name__
        try:
            partial = inventory_partial(c, rec) if output_owned else {'output_root_not_owned': True}
        except Exception as inventory_error:
            partial = {'retained_metadata_inventory_error': str(inventory_error)}
        rec.event('supervisor_stopped', phase=phase, error=message)
        rec.save(phase=phase, scan_completed=False, error=message, stopped_utc=gate.utc_now(),
                 partial_outputs_retained=True, output_manifest_may_be_partial=True, **partial)
        rec.write_json('supervisor-exit.json', {'exit_code': 2 if phase == 'incomplete' else 1,
                       'phase': phase, 'error': message, 'utc': gate.utc_now()})
        return 2 if phase == 'incomplete' else 1


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('image', 'preservation-state', 'preservation-exit-code', 'gate-module', 'approved-tools',
                 'photorec-dir', 'tsk-bin', 'state-dir', 'output-dir'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('partition-number', 'partition-offset', 'partition-length', 'sector-size'):
        p.add_argument('--' + name, type=int, required=True)
    p.add_argument('--max-output-gib', type=float, required=True)
    p.add_argument('--max-files', type=int, default=100000)
    p.add_argument('--max-log-mib', type=int, default=256)
    p.add_argument('--max-hours', type=float, default=24)
    p.add_argument('--poll-seconds', type=float, default=1)
    p.add_argument('--reserve-gib', type=float, default=64)
    p.add_argument('--write-cushion-gib', type=float, default=2)
    a = vars(p.parse_args(argv))
    for name in ('max_output_gib', 'reserve_gib', 'write_cushion_gib', 'max_hours'):
        if not math.isfinite(a[name]) or a[name] <= 0:
            p.error(f'{name} must be positive and finite')
    if a['reserve_gib'] < 64 or a['write_cushion_gib'] < 1:
        p.error('Production CLI requires reserve >= 64 GiB and write cushion >= 1 GiB')
    a['max_output_bytes'] = int(a.pop('max_output_gib') * GIB)
    a['reserve_bytes'] = int(a.pop('reserve_gib') * GIB)
    a['cushion_bytes'] = int(a.pop('write_cushion_gib') * GIB)
    a['max_seconds'] = a.pop('max_hours') * 3600
    a['max_log_bytes'] = a.pop('max_log_mib') * MIB
    return Config(**a)


def main(argv=None):
    c = parse_args(argv)
    if os.name != 'nt':
        raise CarveError('Production supervisor requires Windows job containment and approved native tools')
    return supervise(c)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (CarveError, OSError, ValueError) as error:
        print(f'PhotoRec supervisor refused: {error}', file=sys.stderr)
        sys.exit(1)
