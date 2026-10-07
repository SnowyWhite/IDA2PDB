# Development

## Environment

- **Windows:** `winget configure -f .config/configuration.winget` installs Python, MSYS2 with LLVM/Clang/lld (UCRT64) and the Windows SDK (for `cdb`), and sets `LLVM_CONFIG` machine-wide.  
  Then `python -m pip install -e .`.  
  See [WinGet configuration][winget].
- **Codespaces / Dev Containers:** `.devcontainer/devcontainer.json` provides Ubuntu 24.04 with LLVM 18, Clang and lld, and installs the package into `.venv`.  
  See [Dev Containers](https://containers.dev/).
- **Manual:** Python 3.10+, an LLVM with development files, Clang and lld (e.g. [MSYS2](https://www.msys2.org/) on Windows).  
  `llvm-config` on `PATH` or `LLVM_CONFIG` set.

IDA is only needed for the IDA tests.

## Layout

| Path | Responsibility |
| --- | --- |
| `ida2pdb/model.py` | snapshot schema, validation, serialization |
| `ida2pdb/ida_collect.py` | collection; the only module importing IDA |
| `ida2pdb/codeview.py` | type lowering to CodeView records |
| `ida2pdb/builder.py` | identity checks, symbol placement, writer invocation, report |
| `ida2pdb/pe.py` | PE parsing: sections, image base, RSDS |
| `ida2pdb/toolchain.py` | writer lookup and source builds |
| `ida2pdb/util.py` | process execution with cancellation/timeout, atomic JSON writes |
| `ida2pdb/cli.py` | command line |
| `ida2pdb/native/pdbgen.cxx` | native writer |
| `ida2pdb_plugin.py`, `ida-plugin.json` | IDA plugin |
| `tools/package_plugin.py` | plugin archive |
| `tools/diadump/diadump.cxx` | DIA-based PDB dump for verification |
| `docs/images/pipeline.svg` | source of `pipeline.png` |

## Tests

```sh
python -m unittest discover -s tests
python -m unittest discover -s tests -p "test_codeview.py" -v
```

| Module | Requires | Covers |
| --- | --- | --- |
| `test_model`, `test_codeview`, `test_process` | Python | schema validation, lowering invariants, process control |
| `test_native` | `llvm-config`, `clang++`, `lld-link`, `llvm-pdbutil` | writer and builder on real x86/x64 images |
| `test_native` (debugger cases) | additionally `cdb` on `PATH` | dbghelp's view, compared with the compiler's PDB |
| `test_ida` | `IDA2PDB_TEST_IDA=1`, idalib | IDA -> snapshot -> PDB -> debugger |

Groups skip when their prerequisites are missing.

`tests/fixtures.py` compiles a small C++ program with Clang and links it with lld-link, which also writes `reference.pdb`.  
The image's RSDS record names `fixture.pdb` (`/PDBALTPATH`), so debuggers only see the PDB under test.  
The debugger test requires identical `dt` output from both PDBs for every fixture type.  
`lld-link` is searched on `PATH` and beside `clang++`.  
The writer is cached in `.build/cache`.

The IDA test runs `tests/ida_roundtrip.py` in a separate idalib process (`IDA2PDB_TEST_PYTHON` selects the interpreter), on databases it creates for the fixture.  
It declares the fixture types through IDA's parser, applies them, collects before and after a rebase, builds a strict PDB and compares it in `cdb` with the compiler's, then re-collects the saved database through `ida2pdb collect` and verifies the file is unchanged:

```sh
IDA2PDB_TEST_IDA=1 python -m unittest discover -s tests -p "test_ida.py" -v
```

The plugin's dialogs are not covered; the test only loads and initializes the plugin.

## Verifying PDBs

- **Raw content:** [llvm-pdbutil][llvm-pdbutil]

  ```sh
  llvm-pdbutil dump -summary -types -globals -publics -symbols \
                    -section-contribs app.pdb
  ```

- **dbghelp (WinDbg):** [cdb][cdb] with `-z` maps the image without a process:

  ```sh
  cdb -z app.exe -y C:\symbols\app -c ".reload /f; x app!*; dt app!Player; q"
  ```

- **DIA (x64dbg, Visual Studio):** `tools/diadump`.  
  Build from a Developer Command Prompt (DIA SDK ships with Visual Studio):

  ```bat
  cl /EHsc /O2 /std:c++17 /I "%VSINSTALLDIR%DIA SDK\include" ^
     tools\diadump\diadump.cxx /link ^
     "%VSINSTALLDIR%DIA SDK\lib\amd64\diaguids.lib" ^
     ole32.lib oleaut32.lib advapi32.lib
  ```

  It loads the given `msdia140.dll` without registration; pass x64dbg's (`x64` folder, also reads x86 PDBs) to reproduce x64dbg's view:

  ```sh
  diadump <x64dbg>\x64\msdia140.dll app.exe C:\symbols\app 0x1000
  ```

  Output: the matched identity, all publics, functions, globals, typedefs, UDTs (with members and bitfields) and enums, then `findSymbolByRVA` results for the given RVAs.  
  `loadDataForExe` also searches the image's directory; keep other PDBs out of it.

## Diagram

`docs/images/pipeline.png` is rendered from `pipeline.svg` with a headless Chromium-based browser, which requires a `file:///` URL (PowerShell, from the repository root):

```powershell
$svg = (Resolve-Path docs/images/pipeline.svg).Path
msedge --headless --hide-scrollbars --force-device-scale-factor=2 `
       --window-size=1200,460 `
       "--screenshot=$PWD\docs\images\pipeline.png" "file:///$svg"
```

## Releases

Push a `v*` tag:

```sh
git tag v1.0.0 && git push origin v1.0.0
```

`.github/workflows/release.yml` reuses `build.yml` (tests on Windows and Linux, static writer, plugin archive with the writer bundled under `ida2pdb/bin/`, sdist and wheel) and publishes the artifacts as a GitHub release.  
The tag is the only version source; the package version is derived from it by [setuptools-scm](https://setuptools-scm.readthedocs.io/).

Local equivalent:

```sh
ida2pdb build-writer --static -o dist/ida2pdb-pdbgen.exe
python tools/package_plugin.py dist/ida2pdb.zip \
       --writer dist/ida2pdb-pdbgen.exe
```

## Conventions

- Python: standard library only, 3.10+.
- C++: two-space indentation, a space before parentheses; comments explain rationale and close with an empty `//` line.
- Diagnostics are interface: any new loss path gets a code, is reported, and is listed in the README.

[winget]: https://learn.microsoft.com/en-us/windows/package-manager/configuration/
[llvm-pdbutil]: https://llvm.org/docs/CommandGuide/llvm-pdbutil.html
[cdb]: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/cdb-command-line-options
