"""Synthetic header fixtures; no case media."""
import unittest
import struct
from pathlib import Path
import probe_recovered_media as m

def mp3():
    h=bytes.fromhex('fffb9000');length=m.mp3_frame(h,0)[0]
    return (h+bytes(length-4))*2

class HeaderTests(unittest.TestCase):
    def test_mp3_frames_and_bounded_id3(self):
        raw=mp3();self.assertEqual(m.signature(raw),'mp3')
        for v in (2,3,4):
            self.assertEqual(m.signature(b'ID3'+bytes([v,0,0])+b'\0\0\0\x04'+b'test'+raw),'mp3')
        tag=b'ID3\x04\0\x10\0\0\0\x04'
        self.assertEqual(m.signature(tag+b'test'+b'3DI'+tag[3:]+raw),'mp3')
        for payload in (raw[:4],raw[:-1],b'ID3\x04\0\0\0\0\0\0fLaC'+raw,
                        b'ID3\x04\0\0\x80\0\0\0'+raw,b'ID3\x04\0\0\x00\x04\x00\x00'+raw,
                        b'ID3\x03\0\x01\0\0\0\0'+raw,b'ID3\x04\0\x10\0\0\0\0'+raw):
            self.assertIsNone(m.signature(payload))
        self.assertIsNone(m.signature(bytes.fromhex('fffb0000')+bytes(1000)))
        self.assertIsNone(m.signature(bytes.fromhex('ffeb9000')+bytes(1000)))

    def test_avi_flv_asf_structures_and_false_prefixes(self):
        avi=b'RIFF'+struct.pack('<I',100)+b'AVI LIST'+struct.pack('<I',20)+b'hdrl'
        self.assertEqual(m.signature(avi),'avi')
        self.assertIsNone(m.signature(avi.replace(b'AVI ',b'WEBP')))
        self.assertIsNone(m.signature(avi[:12]))
        flv=b'FLV\x01\x05\0\0\0\x09'+bytes(4)
        self.assertEqual(m.signature(flv),'flv')
        for at,value in ((3,2),(4,0),(4,7),(8,255),(12,1)):
            raw=bytearray(flv);raw[at]=value;self.assertIsNone(m.signature(raw))
        guid=bytes.fromhex('3026b2758e66cf11a6d900aa0062ce6c')
        asf=guid+struct.pack('<QI',54,1)+b'\x01\x02'+bytes([1])*16+struct.pack('<Q',24)
        self.assertEqual(m.signature(asf),'asf')
        for at,value in ((0,0),(16,255),(24,2),(28,0),(46,23)):
            raw=bytearray(asf);raw[at]=value;self.assertIsNone(m.signature(raw))
        self.assertIsNone(m.signature(asf[:-1]))

    def test_ftyp_brands_size_and_header_bounds(self):
        for brand in (b'M4A ',b'3gp4',b'3gp5',b'3gp6',b'3gp7',b'3ge6',b'3gg6',b'3g2a',b'3g2b',b'3g2c'):
            self.assertEqual(m.signature(struct.pack('>I',16)+b'ftyp'+brand+bytes(4)),'mov')
        for raw in (struct.pack('>I',24)+b'ftypisom'+bytes(4),struct.pack('>I',16)+b'ftyp????'+bytes(4),
                    struct.pack('>I',65536)+b'ftypM4A '+bytes(4),mp3()+bytes(m.HEADER_BYTES)):
            self.assertIsNone(m.signature(raw))

    def test_mpeg_false_prefix_and_sequence_bounds(self):
        seq=b'\0\0\x01\xb3'+bytes.fromhex('08006013')+b'\0\0\x20\0'
        self.assertEqual(m.signature(seq),'mpegvideo')
        for at,value in ((4,0),(7,0),(10,0)):
            raw=bytearray(seq);raw[at]=value
            if at==4:raw[5]=0
            self.assertIsNone(m.signature(raw))
        self.assertIsNone(m.signature(b'\0\0\x01\xba'+bytes(64)))

    def test_mpeg_pack_markers_and_stuffing_bounds(self):
        mpeg1 = b'\0\0\x01\xba' + bytes.fromhex('2100010001800001') + b'\0\0\x01'
        mpeg2 = b'\0\0\x01\xba' + bytes.fromhex('440004000401000003f8') + b'\0\0\x01'
        for raw, marker_positions in ((mpeg1, (4, 6, 8, 9, 11)), (mpeg2, (4, 6, 8, 9, 12, 13))):
            self.assertEqual(m.signature(raw), 'mpeg')
            for at in marker_positions:
                malformed = bytearray(raw)
                malformed[at] = 0
                self.assertIsNone(m.signature(malformed))
            self.assertIsNone(m.signature(raw[:-1]))
        stuffed = mpeg2[:13] + b'\xfb' + b'\xff' * 3 + b'\0\0\x01'
        self.assertEqual(m.signature(stuffed), 'mpeg')
        self.assertIsNone(m.signature(stuffed[:-1]))

    def test_all_demuxers_remain_forced_file_only(self):
        tools={'ffprobe':['ffprobe.exe'],'exiftool':['exiftool.exe']}
        for demux in m.DEMUXERS:
            commands=m.commands(tools,Path('fixture.bin'),demux);ff=commands['ffprobe'];exif=commands['exiftool']
            self.assertEqual(ff[ff.index('-f')+1],demux)
            self.assertEqual(ff[ff.index('-format_whitelist')+1],demux)
            self.assertEqual(ff[ff.index('-protocol_whitelist')+1],'file')
            self.assertEqual(exif[1:3],['-config',''])
            if demux=='mov':
                self.assertEqual(ff[ff.index('-enable_drefs')+1],'0')
                self.assertEqual(ff[ff.index('-use_absolute_path')+1],'0')
        for demux in ('concat', 'hls', 'dash', 'image2', 'avisynth'):
            with self.assertRaises(m.ProbeError):m.commands(tools,Path('fixture.bin'),demux)

if __name__=='__main__':unittest.main()
