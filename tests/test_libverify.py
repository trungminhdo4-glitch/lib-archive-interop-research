"""Unit tests for libverify (no toolchain output needed).

All .lib bytes are hand-built with struct (own construction). Covers:
member walk, both linker members, longname resolution, agreement and
disagreement verdicts, malformed inputs -> LibError / exit codes.
"""

import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from libverify import LibError, parse_members, verify


def member(name16: bytes, body: bytes) -> bytes:
    assert len(name16) == 16
    header = name16 + b"0           0     0     0       "
    header += ("%d" % len(body)).encode("ascii").ljust(10) + b"`\n"
    assert len(header) == 60
    blob = header + body
    if len(body) & 1:
        blob += b"\n"
    return blob


def linker1(symbols):
    body = struct.pack(">I", len(symbols))
    body += struct.pack(">%dI" % len(symbols), *(off for _, off in symbols))
    for name, _ in symbols:
        body += name + b"\x00"
    return body


def linker2(entries, member_offsets):
    body = struct.pack("<I", len(member_offsets))
    body += struct.pack("<%dI" % len(member_offsets), *member_offsets)
    body += struct.pack("<I", len(entries))
    body += struct.pack("<%dH" % len(entries), *(m for _, m in entries))
    for name, _ in entries:
        body += name + b"\x00"
    return body


def tiny_lib(disagree=False, longname=False):
    obj = b"\x64\x86" + b"\x00" * 18  # stub body, never parsed here
    if longname:
        names = b"a_very_long_object_name.obj\x00"
        pad_names = names if len(names) % 2 == 0 else names + b"\n"
        obj_hdr = 8 + (60 + 10) + (60 + 16) + (60 + len(pad_names))
        m1 = linker1([(b"f", obj_hdr)])
        m2 = linker2([(b"f", 1)], [obj_hdr])
        lib = (
            b"!<arch>\n"
            + member(b"/               ", m1)
            + member(b"/               ", m2)
            + member(b"//              ", names)
            + member(b"/0              ", obj)
        )
    else:
        obj_hdr = 8 + (60 + 10) + (60 + 16)
        m1 = linker1([(b"f", obj_hdr)])
        m2 = linker2([(b"f", 1)], [999 if disagree else obj_hdr])
        lib = (
            b"!<arch>\n"
            + member(b"/               ", m1)
            + member(b"/               ", m2)
            + member(b"f.obj/          ", obj)
        )
    return lib


class TestLibVerify(unittest.TestCase):
    def _verify(self, data: bytes) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "t.lib"
            path.write_bytes(data)
            return verify(path)

    def test_agreeing_members(self):
        report = self._verify(tiny_lib())
        self.assertTrue(report["agree"])
        self.assertEqual(report["n_symbols_m1"], 1)
        self.assertTrue(report["offsets_agree"])
        self.assertTrue(report["offsets_on_headers_m1"])
        self.assertTrue(report["offsets_on_headers_m2"])

    def test_longname_resolution(self):
        report = self._verify(tiny_lib(longname=True))
        self.assertTrue(report["agree"])
        self.assertTrue(report["has_longnames"])
        self.assertEqual(report["member_names"][0]["kind"], "longname")
        self.assertEqual(
            report["member_names"][0]["name"], "a_very_long_object_name.obj"
        )

    def test_disagreement_detected(self):
        report = self._verify(tiny_lib(disagree=True))
        self.assertFalse(report["agree"])
        self.assertFalse(report["offsets_agree"])

    def test_bad_magic_rejected(self):
        with self.assertRaises(LibError):
            self._verify(b"not an archive at all.............")

    def test_truncated_member_rejected(self):
        with self.assertRaises(LibError):
            self._verify(b"!<arch>\n" + b"/               " + b"12")

    def test_member_walk_counts(self):
        members = parse_members(tiny_lib())
        self.assertEqual(len(members), 3)
        self.assertEqual([m["name_raw"] for m in members], ["/", "/", "f.obj/"])

    def _two_obj_lib(self, m1_idx, m2_entries):
        # Correct-offset builder for 2 regular members; m1_idx lists
        # (name, reg_index_0based), m2_entries lists (name, m2_offs_1based).
        obj = b"\x64\x86" + b"\x00" * 18
        obj2 = b"\x64\x86" + b"\x11" * 18
        m1_dummy = linker1([(n, 0) for n, _ in m1_idx])
        m2_dummy = linker2([(n, 1) for n, _ in m2_entries], [0, 0])
        off = 8 + (60 + len(m1_dummy) + (len(m1_dummy) & 1))
        off += 60 + len(m2_dummy) + (len(m2_dummy) & 1)
        hdrs = [off, off + 60 + len(obj) + (len(obj) & 1)]
        m1 = linker1([(n, hdrs[i]) for n, i in m1_idx])
        m2offs = hdrs
        m2 = linker2(list(m2_entries), list(m2offs))
        assert len(m1) == len(m1_dummy) and len(m2) == len(m2_dummy)
        return (
            b"!<arch>\n"
            + member(b"/               ", m1)
            + member(b"/               ", m2)
            + member(b"f.obj/          ", obj)
            + member(b"g.obj/          ", obj2)
        )

    def test_duplicate_symbol_multiplicity_detected(self):
        # H1e: m1 encodes f twice (two members), m2 encodes f once
        # matching only the last occurrence. Dict collapse hides the
        # extra entry; multiset comparison must DISAGREE.
        lib = self._two_obj_lib([(b"f", 0), (b"f", 1)], [(b"f", 2)])
        report = self._verify(lib)
        self.assertEqual(report["n_symbols_m1"], 2)
        self.assertEqual(report["n_symbols_m2"], 1)
        self.assertFalse(report["offsets_agree"])
        self.assertFalse(report["agree"])

    def test_m2_unreferenced_offset_rejected(self):
        # H3a: m2 offs table carries garbage in an unreferenced slot.
        # RQ2 requires every linker-member offset on a header.
        obj = b"\x64\x86" + b"\x00" * 18
        m1_tmp = linker1([(b"f", 0)])
        m2_tmp = linker2([(b"f", 1)], [0, 0xDEADBEEF])
        hdr = (
            8
            + (60 + len(m1_tmp) + (len(m1_tmp) & 1))
            + (60 + len(m2_tmp) + (len(m2_tmp) & 1))
        )
        m1 = linker1([(b"f", hdr)])
        m2 = linker2([(b"f", 1)], [hdr, 0xDEADBEEF])
        lib = (
            b"!<arch>\n"
            + member(b"/               ", m1)
            + member(b"/               ", m2)
            + member(b"f.obj/          ", obj)
        )
        report = self._verify(lib)
        self.assertFalse(report["offsets_on_headers_m2"])
        self.assertFalse(report["agree"])


if __name__ == "__main__":
    unittest.main()
