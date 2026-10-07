import unittest

from ida2pdb import codeview
from ida2pdb.codeview import FIRST_RECORD, NOTYPE, SIMPLE, Lowering
from ida2pdb.model import Enum, Image, Member, Snapshot, Struct, Typedef


def lower(types, arch="x64"):
    return Lowering(Snapshot(Image(arch, 0x400000), [], types))


def references(record):
    """Every type index a writer input record refers to."""
    keys = {"type", "referent", "element", "index", "return", "args", "fields", "underlying"}
    out = [v for k, v in record.items() if k in keys and isinstance(v, int)]
    if record["leaf"] == "arglist":
        out += record["args"]
    if record["leaf"] == "fieldlist":
        out += [f["type"] for f in record["fields"] if "type" in f]
    return out


class LoweringTests(unittest.TestCase):
    def finish(self, lowering):
        lowering.finish()
        for position, record in enumerate(lowering.records):
            for index in references(record):
                self.assertTrue(index < FIRST_RECORD or index - FIRST_RECORD < position,
                                f"record {position} {record} refers forward to {index:#x}")
        return lowering

    def record(self, lowering, index):
        return lowering.records[index - FIRST_RECORD]

    def test_builtins_and_pointers_to_them_are_simple_types(self):
        lowering = lower({})
        self.assertEqual(lowering.index("int32"), 0x74)
        self.assertEqual(lowering.index({"pointer": "void"}), 0x0603)
        self.assertEqual(lowering.index({"pointer": "char", "size": 4}), 0x0470)
        self.assertEqual(lower({}, "x86").index({"pointer": "uint8"}), 0x0420)
        self.assertEqual(lowering.records, [])

    def test_qualified_and_nested_pointers_are_records(self):
        lowering = lower({"HANDLE": Typedef({"pointer": "void"})})
        double = self.record(lowering, lowering.index({"pointer": {"pointer": "void"}}))
        self.assertEqual(double, {"leaf": "pointer", "referent": 0x0603, "size": 8, "const": False,
                                  "volatile": False})
        const_handle = self.record(lowering, lowering.index({"const": {"ref": "HANDLE"}}))
        self.assertEqual((const_handle["leaf"], const_handle["const"]), ("pointer", True))
        const_int = self.record(lowering, lowering.index({"volatile": {"const": "int32"}}))
        self.assertEqual(const_int, {"leaf": "modifier", "type": 0x74, "const": True, "volatile": True})
        self.finish(lowering)

    def test_identical_records_are_written_once(self):
        lowering = lower({})
        first = lowering.index({"pointer": {"pointer": "int32"}})
        self.assertEqual(lowering.index({"pointer": {"pointer": "int32"}}), first)
        self.assertEqual(len(lowering.records), 1)

    def test_named_structures_are_forward_references_defined_later(self):
        node = Struct("struct", 16, [Member("next", {"pointer": {"ref": "Node"}}, 0), Member("value", "int64", 8)])
        lowering = lower({"Node": node})
        forward = lowering.index({"ref": "Node"})
        self.assertEqual(self.record(lowering, forward), {"leaf": "struct", "name": "Node", "forward": True})
        self.finish(lowering)
        definition = lowering.records[-1]
        self.assertEqual((definition["name"], definition["forward"], definition["size"], definition["count"]),
                         ("Node", False, 16, 2))
        fields = self.record(lowering, definition["fields"])["fields"]
        self.assertEqual(self.record(lowering, fields[0]["type"])["referent"], forward)

    def test_unnamed_anonymous_members_are_merged_into_the_parent(self):
        types = {
            "Value::$parts": Struct("struct", 8, [Member("low", "uint32", 0), Member("high", "uint32", 4)],
                                    anonymous=True),
            "Value": Struct("union", 8, [Member("", {"ref": "Value::$parts"}, 0),
                                         Member("parts", {"ref": "Value::$parts"}, 0), Member("quad", "uint64", 0)]),
            "Outer": Struct("struct", 16, [Member("tag", "int32", 0), Member("", {"ref": "Value"}, 8)]),
        }
        lowering = lower(types)
        lowering.define_all()
        self.finish(lowering)
        value = next(r for r in lowering.records if r.get("name") == "Value" and not r["forward"])
        fields = self.record(lowering, value["fields"])["fields"]
        self.assertEqual([(f["name"], f["offset"]) for f in fields],
                         [("low", 0), ("high", 4), ("parts", 0), ("quad", 0)])
        # A named member keeps the anonymous type, defined in place.
        parts = self.record(lowering, fields[2]["type"])
        self.assertEqual((parts["name"], parts["forward"]), ("<unnamed-tag>", False))
        # An unnamed member of a named type is not anonymous: it stays a member.
        outer = next(r for r in lowering.records if r.get("name") == "Outer" and not r["forward"])
        self.assertEqual([f["name"] for f in self.record(lowering, outer["fields"])["fields"]], ["tag", ""])

    def test_bitfields_get_storage_units(self):
        packed = Struct("struct", 8, [
            Member("kind", "uint32", bit_offset=0, bit_width=3),
            Member("count", "uint32", bit_offset=3, bit_width=13),
            Member("high", "uint8", bit_offset=24, bit_width=4),
            Member("spill", "uint16", bit_offset=44, bit_width=8),   # crosses the 2-byte unit at 4
        ])
        lowering = lower({"Packed": packed})
        lowering.define_all()
        self.finish(lowering)
        definition = lowering.records[-1]
        placed = []
        for f in self.record(lowering, definition["fields"])["fields"]:
            bitfield = self.record(lowering, f["type"])
            placed.append((f["name"], f["offset"], bitfield["position"], bitfield["width"], bitfield["type"]))
        self.assertEqual(placed, [("kind", 0, 0, 3, SIMPLE["uint32"]), ("count", 0, 3, 13, SIMPLE["uint32"]),
                                  ("high", 3, 0, 4, SIMPLE["uint8"]), ("spill", 5, 4, 8, SIMPLE["uint16"])])

    def test_enumerations(self):
        lowering = lower({"Kind": Enum("int8", {"NONE": -1, "FIRST": 0})})
        index = lowering.index({"ref": "Kind"})
        record = self.record(lowering, index)
        self.assertEqual((record["leaf"], record["name"], record["underlying"], record["count"]),
                         ("enum", "Kind", SIMPLE["int8"], 2))
        self.assertEqual(self.record(lowering, record["fields"])["fields"],
                         [{"kind": "enumerator", "name": "NONE", "value": -1},
                          {"kind": "enumerator", "name": "FIRST", "value": 0}])
        self.assertEqual(lowering.size({"ref": "Kind"}), 1)

    def test_typedefs_resolve_to_their_targets_and_become_udts(self):
        types = {"Record": Struct("struct", 4, [Member("x", "int32", 0)]),
                 "RecordAlias": Typedef({"ref": "Record"}),
                 "PRecord": Typedef({"pointer": {"ref": "RecordAlias"}}),
                 "LONG": Typedef("int32")}
        lowering = lower(types)
        udts = {u["name"]: u["type"] for u in lowering.typedefs()}
        self.finish(lowering)
        self.assertEqual(udts["LONG"], SIMPLE["int32"])
        self.assertEqual(udts["RecordAlias"], lowering.index({"ref": "Record"}))
        self.assertEqual(self.record(lowering, udts["PRecord"])["referent"], udts["RecordAlias"])
        self.assertEqual(lowering.size({"ref": "PRecord"}), 8)

    def test_typedef_cycles_and_missing_types_are_diagnosed(self):
        lowering = lower({"A": Typedef({"ref": "B"}), "B": Typedef({"pointer": {"ref": "A"}})})
        self.assertNotEqual(lowering.index({"ref": "A"}), None)
        missing = lowering.index({"ref": "Nowhere"})
        self.assertEqual(self.record(lowering, missing), {"leaf": "struct", "name": "Nowhere", "forward": True})
        lowering.index({"pointer": {"ref": "Nowhere"}})
        self.assertEqual(sorted(d.code for d in lowering.diagnostics), ["type_missing", "typedef_cycle"])
        self.finish(lowering)

    def test_functions(self):
        function = {"function": {"return": "void", "params": ["int32", {"pointer": "char"}], "cc": "stdcall",
                                 "varargs": True}}
        for arch, cc in (("x86", codeview.NEAR_STDCALL), ("x64", codeview.NEAR_C)):
            with self.subTest(arch=arch):
                lowering = lower({}, arch)
                procedure = self.record(lowering, lowering.index(function))
                self.assertEqual((procedure["leaf"], procedure["return"], procedure["cc"], procedure["count"]),
                                 ("procedure", SIMPLE["void"], cc, 3))
                args = self.record(lowering, procedure["args"])["args"]
                self.assertEqual(args[0], SIMPLE["int32"])
                self.assertEqual(args[-1], NOTYPE)
        usercall = {"function": {"return": "int32", "params": [], "cc": "usercall"}}
        for arch in ("x86", "x64"):
            lowering = lower({}, arch)
            self.assertEqual(self.record(lowering, lowering.index(usercall))["cc"], codeview.GENERIC)

    def test_arrays_carry_their_size_in_bytes(self):
        lowering = lower({"Record": Struct("struct", 12, [Member("x", "int32", 0)])})
        array = self.record(lowering, lowering.index({"array": {"array": {"ref": "Record"}, "count": 3},
                                                      "count": 2}))
        self.assertEqual((array["size"], array["index"]), (72, codeview.ARRAY_INDEX["x64"]))
        self.assertEqual(self.record(lowering, array["element"])["size"], 36)
        self.assertEqual(lower({}, "x86").size({"array": {"pointer": "void"}, "count": 4}), 16)


if __name__ == "__main__":
    unittest.main()
