"""Integration tests: real PE files, the native writer, and debugger checks.

They need an LLVM development installation (llvm-config, clang++, lld-link,
llvm-pdbutil) and skip without one. The debugger checks additionally need cdb,
the console debugger of Debugging Tools for Windows, which uses the same
engine (dbghelp) as WinDbg; they skip when it is not on PATH.
"""
from contextlib import redirect_stderr
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from ida2pdb.builder import BuildOptions, build_pdb, default_output
from ida2pdb.cli import main
from ida2pdb.errors import ExportError
from ida2pdb.model import Symbol
from ida2pdb.pe import PEImage
from ida2pdb.toolchain import Toolchain
from ida2pdb.util import run, write_json

from fixtures import make_fixture, pdb_dump

ROOT = Path(__file__).resolve().parents[1]


def cdb(exe, symbols, commands):
    """cdb's output for commands, run against exe as an image file (no process)."""
    debugger = shutil.which("cdb")
    begin, end = "IDA2PDB_BEGIN", "IDA2PDB_END"
    script = f'.reload /f; .echo "{begin}"; {"; ".join(commands)}; .echo "{end}"; q'
    result = subprocess.run([debugger, "-z", str(exe), "-y", str(symbols), "-c", script], capture_output=True,
                            text=True, timeout=120)
    out = result.stdout
    return out[out.find(f"\n{begin}\n") + len(begin) + 2:out.find(f"\n{end}\n")]


class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which(os.environ.get("LLVM_CONFIG", "llvm-config")):
            raise unittest.SkipTest("the integration tests need llvm-config, clang++ and lld-link")
        root = ROOT / ".build"
        root.mkdir(exist_ok=True)
        cls.tmp = tempfile.TemporaryDirectory(prefix="native-tests-", dir=root)
        cls.directory = Path(cls.tmp.name)
        cls.tools = Toolchain(cache_dir=root / "cache")
        cls.writer = cls.tools.writer()
        cls.fixtures = {a: make_fixture(cls.directory / a, a, cls.tools) for a in ("x86", "x64")}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def export(self, arch="x64", snapshot=None, options=None, tools=None, name="output.pdb"):
        exe, original, _ = self.fixtures[arch]
        output = self.directory / arch / "out" / name
        report = build_pdb(snapshot or original, exe, output, toolchain=tools or self.tools, options=options)
        return output, report

    def test_types_symbols_and_identity_on_both_architectures(self):
        for arch, (exe, snapshot, _) in self.fixtures.items():
            with self.subTest(arch=arch):
                output, report = self.export(arch, options=BuildOptions(strict=True))
                self.assertEqual((report["functions"], report["globals"], report["typedefs"], report["publics"]),
                                 (2, 4, 1, 6))
                self.assertEqual(report["image"]["identity"], "verified")
                self.assertEqual(report["diagnostics"], [])
                dump = pdb_dump(output, self.tools)
                image = PEImage.read(exe)
                self.assertIn(image.guid.upper(), dump.upper())
                for expected in ("S_GPROC32", "S_GDATA32", "S_PUB32", "S_UDT", "S_LOCAL", "LF_ARRAY", "LF_BITFIELD",
                                 "LF_ENUM", "LF_UNION", "`RecordAlias`", "`<unnamed-tag>`", "SC[.text]"):
                    self.assertIn(expected, dump)

                # Symbol addresses are RVAs: a rebased database gives the same PDB.
                rebased = deepcopy(snapshot)
                rebased.image.image_base += 0x100000
                other, _ = self.export(arch, rebased, name="rebased.pdb")
                self.assertEqual(pdb_dump(other, self.tools), dump)

    @unittest.skipUnless(shutil.which("cdb"), "cdb (Debugging Tools for Windows) is not on PATH")
    def test_debugger_reads_types_like_the_compilers_own_pdb(self):
        # dt output of our PDB must equal that of the PDB clang and lld wrote
        # for the same source, type by type.
        for arch, (exe, _, _) in self.fixtures.items():
            with self.subTest(arch=arch):
                ours = self.directory / arch / "debugger-ours"
                theirs = self.directory / arch / "debugger-theirs"
                build_pdb(self.fixtures[arch][1], exe, ours / "fixture.pdb", toolchain=self.tools)
                theirs.mkdir(exist_ok=True)
                shutil.copy(exe.with_name("reference.pdb"), theirs / "fixture.pdb")
                for name in ("Record", "Color", "Value", "Packed", "Node"):
                    expected = cdb(exe, theirs, [f"dt fixture!{name}"])
                    self.assertNotIn("not found", expected)
                    self.assertEqual(cdb(exe, ours, [f"dt fixture!{name}"]), expected, name)
                text = cdb(exe, ours, ["dt fixture!RecordAlias", "x fixture!renamed_*",
                                       "dt fixture!renamed_packed"])
                self.assertIn("+0x006 tag              : Char", text)
                self.assertIn("fixture!renamed_sample (int)", text)
                self.assertIn("fixture!renamed_node = struct Node", text)
                self.assertIn("count            : 0y0000001100100 (0x64)", text)

    def test_symbol_kinds_without_valid_types_keep_their_publics(self):
        snapshot = deepcopy(self.fixtures["x64"][1])
        snapshot.symbols[0].type = {"pointer": "int32"}            # not a function type
        snapshot.symbols[2].type = {"array": "int32", "count": 1 << 30}  # past its section
        snapshot.symbols.append(Symbol("image_header", 0, "label"))
        _, report = self.export(snapshot=snapshot)
        self.assertEqual((report["functions"], report["globals"], report["publics"]), (1, 3, 6))
        self.assertEqual(sorted(d["code"] for d in report["diagnostics"]),
                         ["invalid_extent", "invalid_function_type", "outside_sections"])

    def test_publics_only(self):
        _, report = self.export(options=BuildOptions(publics_only=True))
        self.assertEqual((report["type_records"], report["functions"], report["globals"], report["typedefs"],
                          report["publics"]), (0, 0, 0, 0, 6))

    def test_strict_failure_leaves_the_previous_pdb(self):
        snapshot = deepcopy(self.fixtures["x64"][1])
        snapshot.symbols.append(Symbol("image_header", 0, "label"))
        output = self.directory / "x64" / "out" / "strict.pdb"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(b"previous PDB")
        with self.assertRaisesRegex(ExportError, "outside_sections"):
            self.export(snapshot=snapshot, options=BuildOptions(strict=True), name="strict.pdb")
        self.assertEqual(output.read_bytes(), b"previous PDB")

    def test_image_identity(self):
        snapshot = deepcopy(self.fixtures["x64"][1])
        snapshot.image.input_sha256 = "0" * 64
        with self.assertRaisesRegex(ExportError, "SHA-256 differs"):
            self.export(snapshot=snapshot)
        _, report = self.export(snapshot=snapshot, options=BuildOptions(strict=True, allow_image_mismatch=True))
        self.assertEqual(report["image"]["identity"], "mismatch")
        snapshot.image.input_sha256 = ""
        _, report = self.export(snapshot=snapshot)
        self.assertEqual(report["image"]["identity"], "unverified")
        snapshot.image.arch = "x86"
        with self.assertRaisesRegex(ExportError, "architecture mismatch"):
            self.export(snapshot=snapshot)

    def test_writer_rejects_invalid_input_without_writing(self):
        exe = self.fixtures["x64"][0]
        path = self.directory / "bad-input.json"
        output = self.directory / "invalid.pdb"
        valid = {"module": "test", "types": [], "procedures": [], "globals": [], "typedefs": [],
                 "publics": [{"name": "ok", "rva": 0x1000, "function": True}]}
        invalid = [
            {"types": None},
            {"publics": [None]},
            {"publics": [{"name": "bad", "rva": -1, "function": True}]},
            {"publics": [{"name": "bad", "rva": 1 << 32, "function": True}]},
            {"publics": [{"name": "header", "rva": 0, "function": False}]},
            {"types": [{"leaf": "pointer", "referent": 0x1000, "size": 8, "const": False, "volatile": False}]},
            {"types": [{"leaf": "bogus"}]},
            {"types": [{"leaf": "struct", "name": "S", "forward": False, "fields": 0x74, "count": 0, "size": 4}]},
            {"globals": [{"name": "g", "rva": 0x1000, "type": 0x1005}]},
            {"procedures": [{"name": "f", "rva": 0x1000, "size": 1, "type": 0x74, "params": []}]},
        ]
        for change in invalid:
            with self.subTest(change=change):
                write_json(path, {**valid, **change})
                result = run([self.writer, exe, path, output], env=self.tools.env, check=False)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("ida2pdb-pdbgen:", result.stderr)
                self.assertFalse(output.exists())

    def test_invalid_executables(self):
        exe = self.fixtures["x64"][0]
        bad = self.directory / "bad.exe"
        for data in (b"MZ", exe.read_bytes().replace(b"RSDS", b"NB10")):
            bad.write_bytes(data)
            with self.assertRaises(ExportError):
                PEImage.read(bad)

    def test_command_line(self):
        exe, snapshot, _ = self.fixtures["x64"]
        path = self.directory / "snapshot.json"
        report = self.directory / "report.json"
        snapshot.save(path)
        # Without -o the PDB goes next to the executable, under the name its
        # RSDS record asks for.
        self.assertEqual(default_output(exe), exe.with_name("fixture.pdb"))
        result = run([sys.executable, "-m", "ida2pdb", "build", path, "--exe", exe, "--report", report, "--json",
                      "--cache-dir", self.tools.cache_dir, "--strict"], env=self.tools.env, cwd=ROOT)
        self.assertEqual(json.loads(result.stdout), json.loads(report.read_text()))
        self.assertEqual(json.loads(report.read_text())["output"], str(exe.with_name("fixture.pdb")))
        self.assertTrue(exe.with_name("fixture.pdb").is_file())
        with redirect_stderr(io.StringIO()) as error:
            self.assertEqual(main(["build", str(path), "--exe", str(exe), "-o", str(exe)]), 1)
        self.assertIn("would overwrite", error.getvalue())


if __name__ == "__main__":
    unittest.main()
