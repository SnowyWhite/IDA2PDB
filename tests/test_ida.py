"""Licensed IDA integration, opt-in: set IDA2PDB_TEST_IDA=1.

It runs ida_roundtrip.py in a separate idalib process (IDA2PDB_TEST_PYTHON
selects the interpreter idalib is set up for) on databases it creates for the
fixture; it never opens any other database. The PDB built from what IDA
collected must describe the fixture's types exactly as the compiler's own PDB
does, and collecting the closed database must leave it unchanged.
"""
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from ida2pdb.builder import BuildOptions, build_pdb
from ida2pdb.model import Snapshot
from ida2pdb.toolchain import Toolchain
from ida2pdb.util import run, write_json

from fixtures import make_fixture
from test_native import ROOT, cdb


@unittest.skipUnless(os.environ.get("IDA2PDB_TEST_IDA") == "1", "set IDA2PDB_TEST_IDA=1 to run the IDA tests")
class IDATests(unittest.TestCase):
    def test_collection_from_ida_to_debugger(self):
        root = ROOT / ".build"
        root.mkdir(exist_ok=True)
        tools = Toolchain(cache_dir=root / "cache")
        python = os.environ.get("IDA2PDB_TEST_PYTHON", sys.executable)
        with tempfile.TemporaryDirectory(prefix="ida-tests-", dir=root) as tmp:
            for arch in ("x86", "x64"):
                with self.subTest(arch=arch):
                    directory = Path(tmp) / arch
                    exe, _, addresses = make_fixture(directory, arch, tools)
                    snapshot_path = directory / "live.json"
                    database = directory / "fixture.i64"
                    config = directory / "config.json"
                    write_json(config, {"exe": str(exe), "addresses": addresses, "snapshot": str(snapshot_path),
                                        "database": str(database)})
                    userdir = directory / "idausr"
                    (userdir / "plugins").mkdir(parents=True)
                    env = {**tools.env, "IDAUSR": str(userdir)}
                    run([python, Path(__file__).with_name("ida_roundtrip.py"), config], env=env, cwd=ROOT)

                    collected = Snapshot.load(snapshot_path)
                    ours = directory / "ours"
                    report = build_pdb(collected, exe, ours / "fixture.pdb", toolchain=tools,
                                       options=BuildOptions(strict=True))
                    self.assertEqual((report["functions"], report["globals"], report["typedefs"]), (2, 4, 1))
                    self.assertEqual(report["image"]["identity"], "verified")

                    if shutil.which("cdb"):
                        theirs = directory / "theirs"
                        theirs.mkdir()
                        shutil.copy(directory / "reference.pdb", theirs / "fixture.pdb")
                        for name in ("Record", "Color", "Value", "Packed", "Node"):
                            self.assertEqual(cdb(exe, ours, [f"dt fixture!{name}"]),
                                             cdb(exe, theirs, [f"dt fixture!{name}"]), name)
                        self.assertIn("renamed_sample (int)", cdb(exe, ours, ["x fixture!renamed_*"]))

                    # The closed database: collected in a private copy, unchanged.
                    digest = hashlib.sha256(database.read_bytes()).hexdigest()
                    closed = directory / "closed.json"
                    result = run([python, "-m", "ida2pdb", "collect", database, "-o", closed,
                                  "--include", "^renamed_"], env=env, cwd=ROOT)
                    self.assertIn("6 symbols", result.stdout)
                    self.assertEqual(Snapshot.load(closed), collected)
                    self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), digest)
                    self.assertFalse(database.with_suffix(".id0").exists())


if __name__ == "__main__":
    unittest.main()
