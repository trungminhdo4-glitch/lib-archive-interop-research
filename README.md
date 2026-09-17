# lib-archive-interop-research

Do the 1st (big-endian) and 2nd (little-endian) linker members of a
COFF archive (`.lib`) describe the same symbol-to-member mapping?
`scripts/libverify.py` answers that per file — stdlib only, no
toolchain needed for the verdict itself.

This project is independent research. It is not affiliated with,
endorsed by, or sponsored by Microsoft. Product names and
trademarks belong to their respective owners. No third-party
binaries are distributed here; every fixture is a C source file
written for this study (shipped system libraries were read-only
oracles, never copied).

## What is this?

A byte-level cross-validation study of the MSVC static-library
archive layer, plus a tiny strict validator:

- Member walk of `!<arch>` archives with 60-byte headers, decode
  of BOTH linker members (`/` + `/`), `/N` longname (`//`)
  resolution, offset-on-header checks — one verdict per file
  (exit 0 = agree / 1 = disagree / 3 = malformed).
- Evidence across 3 own-built flavors (short names, longnames,
  `/def` import lib via `lib.exe`) and read-only probes of
  shipped MSVC 14.50 libraries (43 / 3682 / 231+2 symbols).
- Differential anchor: `dumpbin /linkermember` offsets vs
  inspector member headers (exact match, e.g. 172/838).

## Why does it exist?

The `.obj` layer gets all the attention (including our companion
study `coff-obj-interop-research`); the archive layer — the thing
`link.exe` actually consumes — has public prose (PE/COFF spec §7)
but no minimal cross-checker: `llvm-ar` is heavy, `dumpbin` is
closed, existing scripts build archives but never validate the two
linker members against each other. Anyone validating `.lib`
producers, debugging static links, or teaching object formats gets
exact, reproducible answers here instead of claims.

## Studied versions

- MSVC 19.50: `cl` / `lib.exe` / `link.exe` / `dumpbin` 14.50
  (C++ workload via `vcvars64.bat`).
- Spec: MS PE/COFF `pe-format` archive/import chapters.
- All behavior is pinned to these versions; re-run the build
  commands to re-anchor others.

## What this repo contains

- `scripts/libverify.py` — strict archive validator (member walk,
  BE + LE linker members, longnames, offset checks; `--json`).
  Works on any `.lib`, no toolchain needed.
- `fixtures/` — 4 own sources (`a_add.c`, `b_mul.c`,
  `a_very_long_object_name.c`, `own.def`).
- `tests/` — hand-built archive bytes (agree/disagree/malformed).
- `RESEARCH.md` — full method, hypotheses/falsifiers, all
  findings. `findings.json` — machine-readable claim ledger.

## What it is NOT

- No import-header field decode (members only named), no bigobj
  members in `.lib`, no ARM64, no exploit work, no
  credential/DRM topics (none exist here).

## Quick start (no toolchain needed)

```powershell
# verdict for any .lib file
python scripts\libverify.py <file.lib> [--json]
# unit tests (hand-built bytes only)
python -m pytest tests -q
```

## Reproduction (needs MSVC)

```powershell
# own flavors (from a vcvars64 shell, scratch dir)
copy fixtures\a_add.c fixtures\b_mul.c <scratch>
cl /nologo /c a_add.c b_mul.c
lib /nologo /out:own.lib a_add.obj b_mul.obj
cl /nologo /c <scratch>\a_very_long_object_name.c  # long-name flavor
lib /nologo /out:long.lib a_very_long_object_name.obj
lib /nologo /def:fixtures\own.def /out:own_imp.lib /machine:x64
python scripts\libverify.py own.lib
```

## Key findings (short)

- 6/6 archives AGREE: identical name->offset maps between the BE
  and LE linker members, every offset lands on a member header —
  own-built (2/2, 1/1, 7/7 symbols) and shipped 14.50 libraries
  (43/3682/231+2 symbols).
- `//` longnames are optional (only emitted with >15-char member
  names); short names carry a trailing `/`; import libraries keep
  the same discipline with the DLL name as member name.

See `RESEARCH.md` for the full evidence and `findings.json` for
per-claim confidence and explicit non-findings.

## Limitations

Pinned to MSVC/lib 14.50. Import-header internals, bigobj members
in `.lib`, and ARM64 are explicit non-findings (see
`findings.json`).

## License

MIT - see `LICENSE`. Our scripts, docs, and fixtures are our own
work.
