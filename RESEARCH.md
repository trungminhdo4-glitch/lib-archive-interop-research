# MSVC COFF archives — linker-member cross-validation

Target: `.lib` as emitted by MSVC `lib.exe` 14.50 (x86-64):
do the 1st (big-endian) and 2nd (little-endian) linker members
describe the same symbol->member mapping? Status: RESEARCH_COMPLETE.
OBSERVED unless marked INFERRED/UNKNOWN.

## 1. Provenance (no vendor binary involved)

- Fixtures are own C sources (`fixtures/a_add.c`, `b_mul.c`,
  `a_very_long_object_name.c`, `own.def`), compiled locally with
  MSVC 19.50 (a standard Visual Studio install with the C++ workload,
  via `vcvars64.bat`) and archived
  with `lib.exe` 14.50 (regular, long-name, and `/def` import-lib
  flavors — all own files, license-clean normal toolchain use).
- Shipped MSVC `.lib` files (`CppUnitTestFramework`, `msvcprt`,
  `vcomp`, `stl_asan`) were read ONLY as oracles — never copied,
  never committed.
- Cross-oracles: MS dumpbin 19.50 (`/linkermember`, `/headers`).
- License: own fixtures + clean-room parser. LICENSE_GREEN.
- Spec: MS PE/COFF `pe-format` archive/import chapters (cited, not
  pasted); Pietrek 1998; Rust `object` crate behavior (BAEE).

## 2. Research questions

- RQ1: Do the 1st and 2nd linker members of real 14.50 `.lib` output
  agree symbol-for-symbol (name->member-offset map)?
- RQ2: Does every linker-member offset land exactly on a member
  header, and does every `/N` longname resolve?
- RQ3: Does this hold across archive flavors (short names,
  longnames `//`, import libraries)?

PRIMARY FALSIFIER: the first file where the two members disagree,
or an offset misses a header, kills the agreement claim.

## 3. Method

Oracle-first, then minimal corpus: parse a shipped `.lib` read-only
in memory (member walk + both linker members), fix two analyst-side
bugs (a phantom second count word; positional instead of
name-keyed comparison), then build own `.lib` flavors with `lib.exe`
and assert the same invariant with `scripts/libverify.py`
(stdlib-only, exit 0 = agree / 1 = disagree / 3 = malformed).
Differential anchor: `dumpbin /linkermember` offsets vs inspector
member headers (own.lib: dumpbin f@0xAC/add@0x346 = headers
172/838 — exact match).

## 4. Findings

| File | Origin | m1/m2 symbols | Verdict |
| ---- | ------ | ------------- | ------- |
| own.lib | own (`lib.exe`, short names) | 2/2 | AGREE |
| long.lib | own (`//` longnames) | 1/1 | AGREE, `/0` resolves |
| own_imp.lib | own (`/def` import lib) | 7/7 | AGREE, members named `own.dll/` |
| CppUnitTestFramework.lib | shipped 14.50 | 43/43 | AGREE |
| msvcprt.lib | shipped 14.50 | 3682/3682 | AGREE |
| vcomp.lib / stl_asan.lib | shipped 14.50 | 231/2 | AGREE |

- L1: 6/6 archives AGREE — name->offset maps identical between the
  BE and LE linker members; every offset lands on a member header.
- L2: `//` longnames are optional (emitted only when a member name
  exceeds 15 chars); `/N` references resolve; short names carry a
  trailing `/`.
- L3: import libraries keep the same linker-member discipline;
  import-header members use the target DLL name as member name.
- L4: `/GL` objects were NOT archived here (LTCG/ClassID lane stays
  in the COFF-obj study) — explicit scope cut.

## 5. Hypotheses ledger

- H-agree: "both linker members describe the same mapping on real
  14.50 output" -> CONFIRMED (6/6, incl. 3682-symbol file).
- H-offsets: "every offset lands on a member header" -> CONFIRMED.
- H-longnames: "`//` always present" -> REFUTED (optional; only
  with long names).

## 6. Unknowns (explicit)

- Import-header member internals (sig/version/type/age fields) —
  not decoded, only named; own study material if needed.
- bigobj members inside `.lib` (untested — `/bigobj` objects were
  not archived; not absent).
- ARM64 `.lib` (no cross toolchain locally).

## 7. Reproduction

```powershell
# oracle probes (read-only, nothing committed)
python scripts\libverify.py <file.lib> [--json]
# own-flavor builds (needs VS with C++ workload, scratch dir):
copy fixtures\a_add.c fixtures\b_mul.c <scratch>
cl /nologo /c a_add.c b_mul.c
lib /nologo /out:own.lib a_add.obj b_mul.obj
cl /nologo /c ..\fixtures\a_very_long_object_name.c  # long name flavor
lib /nologo /out:long.lib a_very_long_object_name.obj
lib /nologo /def:fixtures\own.def /out:own_imp.lib /machine:x64
# unit tests (no toolchain needed, hand-built bytes only)
python -m pytest tests -q
```

## 8. Environment gotchas (pinned)

- `New-Item` with forward slashes fails here (`FileSystem.access`);
  use backslash paths on this box.
- `cmd /c 'call "<vcvars>" >nul && ...'` quoting works from the
  shell; from Python use staged runner `.bat` files instead.
- Local pytest needs `-p no:dash` (broken site `dash` plugin);
  CI installs only pytest and is unaffected.
