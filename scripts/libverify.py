"""Cross-validate the two linker members of a COFF archive (.lib).

Answers one mechanical question per file: do the 1st (big-endian) and
2nd (little-endian) linker members describe the same symbol->member
mapping, do all offsets land on member headers, and do /N longnames
resolve? Stdlib only.

Usage:
  python libverify.py <file.lib> [--json]
Exit: 0 = members agree, 1 = disagreement, 3 = malformed archive.
"""

import json
import struct
import sys
from collections import Counter
from pathlib import Path

ARCH_MAGIC = b"!<arch>\n"
HEADER_LEN = 60


class LibError(Exception):
    pass


def need(data, off, size, what):
    if off < 0 or size < 0 or off + size > len(data):
        raise LibError(
            "%s out of range (off=%d size=%d len=%d)" % (what, off, size, len(data))
        )
    return data[off : off + size]


def parse_members(data):
    if data[:8] != ARCH_MAGIC:
        raise LibError("bad archive magic %r" % data[:8])
    members = []
    off = 8
    while off < len(data):
        hdr = need(data, off, HEADER_LEN, "member header")
        try:
            size = int(hdr[48:58].decode("ascii").strip() or "0")
        except ValueError:
            raise LibError("bad member size at %d" % off)
        members.append(
            {
                "index": len(members),
                "name_raw": hdr[:16].rstrip(b" ").decode("ascii", "replace"),
                "header_offset": off,
                "body_offset": off + HEADER_LEN,
                "size": size,
            }
        )
        off += HEADER_LEN + size + (size & 1)
    if off != len(data):
        raise LibError("trailing %d bytes after last member" % (len(data) - off))
    return members


def decode_first_member(body):
    if len(body) < 4:
        raise LibError("first linker member too short")
    count = struct.unpack(">I", body[:4])[0]
    offs = list(struct.unpack(">%dI" % count, need(body, 4, 4 * count, "m1 offsets")))
    names = need(body, 4 + 4 * count, len(body) - 4 - 4 * count, "m1 strings")
    parts = names.split(b"\x00")
    if parts and parts[-1] == b"":
        parts.pop()
    if len(parts) != count:
        raise LibError("m1 name count %d != %d" % (len(parts), count))
    # Preserve every encoded occurrence: m1 is member-ordered while m2 is
    # lexical, so cross-member comparison must be order-insensitive but
    # multiplicity-sensitive. A dict would silently collapse duplicates.
    entries = [(p.decode("ascii", "replace"), o) for p, o in zip(parts, offs)]
    return {"count": count, "entries": entries}


def decode_second_member(body):
    if len(body) < 4:
        raise LibError("second linker member too short")
    nmembers = struct.unpack("<I", body[:4])[0]
    offs = list(
        struct.unpack("<%dI" % nmembers, need(body, 4, 4 * nmembers, "m2 offsets"))
    )
    rest = 4 + 4 * nmembers
    nsyms = struct.unpack("<I", need(body, rest, 4, "m2 symcount"))[0]
    idx = list(
        struct.unpack("<%dH" % nsyms, need(body, rest + 4, 2 * nsyms, "m2 indices"))
    )
    if any(i < 1 or i > nmembers for i in idx):
        raise LibError("m2 member index out of range")
    names = need(
        body, rest + 4 + 2 * nsyms, len(body) - rest - 4 - 2 * nsyms, "m2 strings"
    )
    parts = names.split(b"\x00")
    if parts and parts[-1] == b"":
        parts.pop()
    if len(parts) != nsyms:
        raise LibError("m2 name count %d != %d" % (len(parts), nsyms))
    # Preserve the raw offset table (unreferenced slots must still land on
    # headers per RQ2) plus every symbol occurrence for multiset agreement.
    entries = [(p.decode("ascii", "replace"), offs[i - 1]) for p, i in zip(parts, idx)]
    return {
        "nmembers": nmembers,
        "offs": offs,
        "nsyms": nsyms,
        "indices": idx,
        "entries": entries,
    }


def resolve_name(raw, longnames):
    if raw.startswith("//"):
        return ("longnames", None)
    if raw.startswith("/"):
        try:
            at = int(raw[1:].rstrip("/"))
        except ValueError:
            raise LibError("bad longname reference %r" % raw)
        end = longnames.find(b"\x00", at)
        if end < 0:
            raise LibError("longname offset %d unresolved" % at)
        return ("longname", longnames[at:end].decode("ascii", "replace"))
    if raw.endswith("/"):
        return ("short", raw[:-1])
    return ("object", raw)


def verify(path):
    data = Path(path).read_bytes()
    report = {
        "file": str(path),
        "bytes": len(data),
        "sha256": __import__("hashlib").sha256(data).hexdigest(),
    }
    members = parse_members(data)
    report["n_members"] = len(members)
    if (
        len(members) < 2
        or members[0]["name_raw"] != "/"
        or members[1]["name_raw"] != "/"
    ):
        raise LibError("missing /,/ linker members")
    first_regular = 2
    longnames = b""
    if len(members) > 2 and members[2]["name_raw"] == "//":
        longnames = data[
            members[2]["body_offset"] : members[2]["body_offset"] + members[2]["size"]
        ]
        first_regular = 3
    report["has_longnames"] = bool(longnames)
    m1 = decode_first_member(
        data[members[0]["body_offset"] : members[0]["body_offset"] + members[0]["size"]]
    )
    m2 = decode_second_member(
        data[members[1]["body_offset"] : members[1]["body_offset"] + members[1]["size"]]
    )
    headers = {m["header_offset"] for m in members}
    report["n_symbols_m1"] = m1["count"]
    report["n_symbols_m2"] = m2["nsyms"]
    report["symbols_equal"] = {n for n, _ in m1["entries"]} == {
        n for n, _ in m2["entries"]
    }
    # Order-insensitive (m1 member-ordered, m2 lexical per spec) but
    # multiplicity-sensitive: duplicate occurrences must match exactly.
    report["offsets_agree"] = Counter(m1["entries"]) == Counter(m2["entries"])
    report["offsets_on_headers_m1"] = all(o in headers for _, o in m1["entries"])
    report["offsets_on_headers_m2"] = all(
        o in headers for _, o in m2["entries"]
    ) and all(o in headers for o in m2["offs"])
    resolved = []
    for m in members[first_regular:]:
        kind, name = resolve_name(m["name_raw"], longnames)
        resolved.append(
            {"header_offset": m["header_offset"], "kind": kind, "name": name}
        )
    report["member_names"] = resolved
    report["longnames_resolve"] = all(
        r["name"] is not None for r in resolved if r["kind"] == "longname"
    )
    report["agree"] = (
        report["offsets_agree"]
        and report["offsets_on_headers_m1"]
        and report["offsets_on_headers_m2"]
        and report["longnames_resolve"]
    )
    return report


def main(argv=None):
    args = argv if argv is not None else sys.argv[1:]
    as_json = "--json" in args
    files = [a for a in args if not a.startswith("-")]
    if len(files) != 1:
        print("usage: libverify.py <file.lib> [--json]", file=sys.stderr)
        return 2
    try:
        report = verify(files[0])
    except (LibError, ValueError, struct.error) as exc:
        payload = {"ok": False, "error": str(exc)}
        print(
            json.dumps(payload) if as_json else "MALFORMED: %s" % exc,
            file=sys.stderr if as_json else sys.stdout,
        )
        return 3
    if as_json:
        report["ok"] = True
        print(json.dumps(report, indent=2))
    else:
        print(
            "symbols m1=%d m2=%d agree=%s offsets_on_headers=%s/%s "
            "longnames=%s => %s"
            % (
                report["n_symbols_m1"],
                report["n_symbols_m2"],
                report["offsets_agree"],
                report["offsets_on_headers_m1"],
                report["offsets_on_headers_m2"],
                report["longnames_resolve"],
                "AGREE" if report["agree"] else "DISAGREE",
            )
        )
    return 0 if report["agree"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
