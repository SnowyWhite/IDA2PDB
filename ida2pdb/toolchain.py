"""Find the native PDB writer, or build it from the bundled source.

The writer (native/pdbgen.cxx) uses LLVM's PDB libraries, which have no Python
binding. It is looked up in this order:

1. an explicit path (`--pdbgen`, or IDA2PDB_PDBGEN);
2. `ida2pdb-pdbgen` on PATH;
3. a prebuilt writer shipped inside the package (`ida2pdb/bin/`), as the
   release archives of the plugin have it;
4. a build from source against the LLVM that `llvm-config` describes
   (`--llvm-config`, or LLVM_CONFIG), cached by source and toolchain identity.

A shared build links libLLVM dynamically, so LLVM's bin directory is put on
PATH for the writer's process. A static build has no such dependency and can be
copied to machines without LLVM.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import platform
import shlex
import shutil
import tempfile

from .errors import ExportError
from .util import run

SOURCE = Path(__file__).with_name("native") / "pdbgen.cxx"
EXE_SUFFIX = ".exe" if os.name == "nt" else ""
WRITER_NAME = "ida2pdb-pdbgen"
BUNDLED = Path(__file__).with_name("bin") / (WRITER_NAME + EXE_SUFFIX)

# The LLVM components the writer uses, for a static link.
#
LLVM_COMPONENTS = ("debuginfopdb", "debuginfocodeview", "debuginfomsf", "object", "support")


def executable(value) -> Path:
    """A program by name (searched on PATH) or by path."""
    found = shutil.which(str(value))
    if found:
        return Path(found).resolve()
    path = Path(value).expanduser()
    if path.is_file():
        return path.resolve()
    raise ExportError(f"executable not found: {value}")


def cache_directory() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        root = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return root / "ida2pdb"


class Toolchain:
    """The external programs an export runs, and the environment they run in.

    cancel_event, a threading.Event, stops a running program when set.
    """

    def __init__(self, *, pdbgen=None, llvm_config=None, cxx=None, cache_dir=None, cancel_event=None):
        self.pdbgen_path = pdbgen or os.environ.get("IDA2PDB_PDBGEN")
        self.llvm_config = llvm_config or os.environ.get("LLVM_CONFIG", "llvm-config")
        self.cxx = cxx or os.environ.get("IDA2PDB_CXX")
        self.cache_dir = Path(cache_dir) if cache_dir else cache_directory()
        self.env = dict(os.environ)
        self.cancel_event = cancel_event

    def run(self, command, **kwargs):
        return run(command, env=self.env, cancel_event=self.cancel_event, **kwargs)

    def _add_path(self, directory):
        # The shared writer finds libLLVM, and Clang its own DLLs, through PATH.
        directory = str(directory)
        entries = self.env.get("PATH", "").split(os.pathsep)
        if directory not in entries:
            self.env["PATH"] = os.pathsep.join([directory, *filter(None, entries)])

    def writer(self) -> Path:
        """The writer to run, building it on first use."""
        if self.pdbgen_path:
            path = executable(self.pdbgen_path)
        elif found := shutil.which(WRITER_NAME):
            path = Path(found).resolve()
        elif BUNDLED.is_file():
            path = BUNDLED
        else:
            return self.build_writer()
        self._add_path(path.parent)
        return path

    def build_writer(self, output=None, *, static=False) -> Path:
        """Compile the writer, into the cache unless an output path is given."""
        config = executable(self.llvm_config)
        self._add_path(config.parent)
        bindir = Path(self.run([config, "--bindir"]).stdout.strip())
        self._add_path(bindir)
        compiler = executable(self.cxx) if self.cxx else executable(bindir / ("clang++" + EXE_SUFFIX))
        self._add_path(compiler.parent)

        version = self.run([config, "--version"]).stdout.strip()
        # The writer is C++20; LLVM's own -std would override that.
        cxxflags = [f for f in shlex.split(self.run([config, "--cxxflags"]).stdout) if not f.startswith("-std=")]
        if static:
            ldflags = shlex.split(self.run([config, "--ldflags"]).stdout)
            ldflags += ["-static", *shlex.split(self.run([config, "--link-static", "--libs", *LLVM_COMPONENTS]).stdout)]
            # MSYS2 names zstd's import library zstd.dll; the archive is zstd.
            ldflags += [f.replace("-lzstd.dll", "-lzstd")
                        for f in shlex.split(self.run([config, "--link-static", "--system-libs"]).stdout)]
        else:
            ldflags = shlex.split(self.run([config, "--ldflags", "--libs", "--link-shared"]).stdout)

        key = hashlib.sha256(SOURCE.read_bytes() + repr((str(config), str(compiler), version, cxxflags, ldflags,
                                                         static, platform.platform())).encode()).hexdigest()[:20]
        path = Path(output).resolve() if output else self.cache_dir / key / (WRITER_NAME + EXE_SUFFIX)
        if not output and path.is_file():
            return path
        path.parent.mkdir(parents=True, exist_ok=True)

        # A failed compile, or two first-time builds racing, must not leave a
        # partial executable where another process would run it.
        with tempfile.TemporaryDirectory(prefix=".build-", dir=path.parent) as tmp:
            staged = Path(tmp) / path.name
            self.run([compiler, "-std=c++20", "-O2", *cxxflags, SOURCE, "-o", staged, *ldflags], timeout=1800)
            os.replace(staged, path)
        return path
