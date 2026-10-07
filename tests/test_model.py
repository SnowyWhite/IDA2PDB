from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from ida2pdb.errors import ExportError
from ida2pdb.model import Enum, Image, Member, Snapshot, Struct, Symbol, Typedef


def sample_snapshot():
    return Snapshot(
        Image("x64", 0x140000000, "ab" * 32),
        [Symbol("function", 0x1000, "function", 16,
                {"function": {"return": "int32", "params": [{"pointer": {"ref": "Record"}}], "cc": "fastcall"}},
                ["record"]),
         Symbol("record", 0x2000, "data", 8, {"ref": "Record"}),
         Symbol("label", 0x1008, "label")],
        {"Record": Struct("struct", 8, [Member("count", "int32", 0),
                                        Member("flags", "uint16", bit_offset=32, bit_width=3),
                                        Member("", {"ref": "Record::$anon"}, 6)]),
         "Record::$anon": Struct("union", 2, [Member("a", "uint8", 0), Member("b", "int16", 0)], anonymous=True),
         "Kind": Enum("int8", {"NEGATIVE": -1, "ZERO": 0}),
         "RecordPtr": Typedef({"const": {"pointer": {"ref": "Record"}}}),
         "Opaque": Struct("struct")})


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = sample_snapshot()

    def rejects(self, change, pattern=None):
        d = self.snapshot.to_dict()
        change(d)
        with self.assertRaisesRegex(ExportError, pattern or ""):
            Snapshot.from_dict(d)

    def test_roundtrip_preserves_everything(self):
        d = self.snapshot.to_dict()
        self.assertEqual(Snapshot.from_dict(deepcopy(d)), self.snapshot)
        self.assertEqual(Snapshot.from_dict(deepcopy(d)).to_dict(), d)

    def test_defaults_are_left_out(self):
        d = self.snapshot.to_dict()
        self.assertEqual(d["symbols"][2], {"name": "label", "rva": 0x1008, "kind": "label"})
        self.assertEqual(d["types"]["Opaque"], {"kind": "struct"})

    def test_integers_are_checked(self):
        for value in (-1, 1 << 32, True, "4096", 1.5):
            with self.subTest(rva=value):
                self.rejects(lambda d: d["symbols"][0].update(rva=value), "unsigned 32-bit")
        self.rejects(lambda d: d["image"].update(image_base=1 << 64), "64-bit")

    def test_format_and_fields_are_checked(self):
        self.rejects(lambda d: d.update(format="something else"), "not a snapshot")
        self.rejects(lambda d: d.update(version=1), "unknown fields")
        self.rejects(lambda d: d["symbols"][0].pop("kind"), "missing fields")
        self.rejects(lambda d: d["image"].update(input_sha256="AB" * 32), "lowercase")
        self.rejects(lambda d: d["symbols"].append(deepcopy(d["symbols"][0])), "duplicate")

    def test_symbols_are_checked(self):
        self.rejects(lambda d: d["symbols"][2].update(type="int32"), "labels cannot have types")
        self.rejects(lambda d: d["symbols"][1].update(params=["x"]), "only functions")
        self.rejects(lambda d: d["symbols"][0].update(name=""), "nonempty")
        self.rejects(lambda d: d["symbols"][0].update(name="a\0b"), "NUL")
        self.rejects(lambda d: d["symbols"][0].update(name="x" * 60001), "too long")

    def test_type_expressions_are_checked(self):
        for bad in ("int", {"ref": ""}, {"ref": "A", "pointer": "void"}, {"pointer": "void", "size": 2},
                    {"array": "int32"}, {"function": {"return": "void"}},
                    {"function": {"return": "void", "params": [], "cc": "regcall"}}, {"const": "int33"}, [], 1):
            with self.subTest(type=bad):
                self.rejects(lambda d: d["symbols"][1].update(type=bad))

    def test_definitions_are_checked(self):
        self.rejects(lambda d: d["types"]["Record"].update(kind="class"), "expected struct")
        self.rejects(lambda d: d["types"]["Opaque"].update(size=4), "declared-only")
        self.rejects(lambda d: d["types"]["Kind"].update(underlying="float32"), "integer")
        self.rejects(lambda d: d["types"]["Kind"].update(underlying={"ref": "Record"}), "integer")
        self.rejects(lambda d: d["types"]["Kind"]["values"].update(BIG=128), "outside the range")
        members = lambda d: d["types"]["Record"]["members"]  # noqa: E731
        self.rejects(lambda d: members(d)[1].update(offset=4), "bit_offset and bit_width")
        self.rejects(lambda d: members(d)[1].update(bit_width=0), "1 to 64")
        self.rejects(lambda d: members(d)[1].update(type={"ref": "Kind"}), "storage unit")
        self.rejects(lambda d: members(d)[0].update(base=True), "base class must be a named type")
        # What the writer could not encode must not pass validation.
        self.rejects(lambda d: members(d)[1].update(type="uint128"), "at most 64 bits")
        self.rejects(lambda d: members(d)[1].update(type="uint8", bit_width=9), "wider than its storage unit")
        self.rejects(lambda d: d["types"]["Kind"].update(underlying="int128"), "at most 64 bits")
        self.rejects(lambda d: d["symbols"][1].update(type={"pointer": "void", "size": 4.0}), "4 or 8")

    def test_save_validates_and_writes_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            self.snapshot.save(path)
            self.assertEqual(Snapshot.load(path), self.snapshot)
            broken = deepcopy(self.snapshot)
            broken.symbols[0].rva = -1
            with self.assertRaises(ExportError):
                broken.save(path)
            self.assertEqual(Snapshot.load(path), self.snapshot)

    def test_validated_returns_an_independent_copy(self):
        copy = self.snapshot.validated()
        copy.types["Record"].members[0].name = "renamed"
        self.assertEqual(self.snapshot.types["Record"].members[0].name, "count")


if __name__ == "__main__":
    unittest.main()
