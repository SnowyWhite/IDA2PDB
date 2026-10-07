"""A tiny PE with known contents, and the snapshot IDA would take of it.

make_fixture() compiles FIXTURE_SOURCE with Clang, links it with lld-link and
returns the executable with a hand-written snapshot whose types describe the
source's types exactly. The linker writes its own PDB too, but the executable's
RSDS record names `fixture.pdb`, so debuggers only find the PDB under test.
"""
from __future__ import annotations

from pathlib import Path
import re
import shutil

from ida2pdb.model import Enum, Image, Member, Snapshot, Struct, Symbol, Typedef
from ida2pdb.pe import PEImage
from ida2pdb.toolchain import EXE_SUFFIX, Toolchain, executable
from ida2pdb.util import run

# The fixture's types, in C that both Clang and IDA's parser accept.
#
FIXTURE_DECLARATIONS = r'''
struct Record { int count; short flags; char tag; };
typedef struct Record RecordAlias;
enum Color : unsigned char { Red = 1, Green = 2, Blue = 0xff };
union Value { struct { unsigned int low; unsigned int high; }; unsigned long long quad; };
struct Packed { unsigned int kind : 3; unsigned int count : 13; unsigned short tail; };
struct Node { struct Node *next; struct Record record; union Value value; enum Color color; };
'''

FIXTURE_SOURCE = FIXTURE_DECLARATIONS + r'''
extern "C" {
Record record = {7, 3, 'A'};
int values[3] = {1, 2, 3};
Node node = {&node, {1, 2, 'B'}, {{5, 6}}, Green};
Packed packed = {5, 100, 7};
int sample(int value) { return value + record.count + values[0]; }
int variadic(const char *format, ...) { return format[0]; }
void entry() { record.count = sample(1) + variadic("x") + node.record.count + packed.count; }
}
'''

# The same types as IDA would record them.
#
FIXTURE_TYPES = {
    "Record": Struct("struct", 8, [Member("count", "int32", 0), Member("flags", "int16", 4),
                                   Member("tag", "char", 6)]),
    "RecordAlias": Typedef({"ref": "Record"}),
    "Color": Enum("uint8", {"Red": 1, "Green": 2, "Blue": 0xff}),
    "Value::$parts": Struct("struct", 8, [Member("low", "uint32", 0), Member("high", "uint32", 4)],
                            anonymous=True),
    "Value": Struct("union", 8, [Member("", {"ref": "Value::$parts"}, 0), Member("quad", "uint64", 0)]),
    "Packed": Struct("struct", 8, [Member("kind", "uint32", bit_offset=0, bit_width=3),
                                   Member("count", "uint32", bit_offset=3, bit_width=13),
                                   Member("tail", "uint16", 4)]),
}


def linker(toolchain: Toolchain) -> str:
    found = shutil.which("lld-link")
    if found:
        return found
    beside = compiler(toolchain).parent / ("lld-link" + EXE_SUFFIX)
    if not beside.is_file():
        raise RuntimeError("the integration tests need lld-link, on PATH or beside clang++")
    return str(beside)


def compiler(toolchain: Toolchain) -> Path:
    bindir = Path(toolchain.run([toolchain.llvm_config, "--bindir"]).stdout.strip())
    return executable(bindir / ("clang++" + EXE_SUFFIX))


def make_fixture(directory, arch, toolchain: Toolchain):
    """Build the fixture for arch; returns (exe, snapshot, {name: rva})."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    source = directory / "fixture.cpp"
    obj = directory / "fixture.obj"
    exe = directory / "fixture.exe"
    source.write_text(FIXTURE_SOURCE, encoding="utf-8")
    triple = "x86_64-pc-windows-msvc" if arch == "x64" else "i686-pc-windows-msvc"
    toolchain.writer()  # puts LLVM's bin directory on the toolchain's PATH
    run([compiler(toolchain), f"--target={triple}", "-c", "-g", "-gcodeview", "-O0", source, "-o", obj],
        env=toolchain.env)
    run([linker(toolchain), obj, f"/out:{exe}", f"/pdb:{directory / 'reference.pdb'}", "/pdbaltpath:fixture.pdb",
         f"/map:{directory / 'fixture.map'}", "/entry:entry", "/subsystem:console", "/nodefaultlib", "/debug",
         "/opt:noref", "/opt:noicf", "/export:sample", "/export:record,DATA", "/export:values,DATA"],
        env=toolchain.env)

    image = PEImage.read(exe)
    addresses = {}
    for line in (directory / "fixture.map").read_text().splitlines():
        m = re.match(r"\s+[0-9a-fA-F]{4}:[0-9a-fA-F]+\s+(\S+)\s+([0-9a-fA-F]{8,16})\s", line)
        if m:
            addresses[m.group(1).lstrip("_")] = int(m.group(2), 16) - image.image_base

    # Function sizes: up to the next function, as IDA would find them.
    code = sorted(addresses[name] for name in ("sample", "variadic", "entry"))
    size = {name: next((a for a in code if a > addresses[name]), addresses[name] + 16) - addresses[name]
            for name in ("sample", "variadic", "entry")}

    # Node's layout depends on the pointer size; the union is 8-aligned on both.
    pointer = 8 if arch == "x64" else 4
    types = dict(FIXTURE_TYPES)
    types["Node"] = Struct("struct", 32, [Member("next", {"pointer": {"ref": "Node"}}, 0),
                                          Member("record", {"ref": "Record"}, pointer),
                                          Member("value", {"ref": "Value"}, 16),
                                          Member("color", {"ref": "Color"}, 24)])
    node_size = 32

    cdecl = {"function": {"return": "int32", "params": ["int32"], "cc": "cdecl"}}
    variadic = {"function": {"return": "int32", "params": [{"pointer": {"const": "char"}}], "cc": "cdecl",
                             "varargs": True}}
    symbols = [
        Symbol("renamed_sample", addresses["sample"], "function", size["sample"], cdecl, ["value"]),
        Symbol("renamed_variadic", addresses["variadic"], "function", size["variadic"], variadic, ["format"]),
        Symbol("renamed_record", addresses["record"], "data", 8, {"ref": "RecordAlias"}),
        Symbol("renamed_values", addresses["values"], "data", 12, {"array": "int32", "count": 3}),
        Symbol("renamed_node", addresses["node"], "data", node_size, {"ref": "Node"}),
        Symbol("renamed_packed", addresses["packed"], "data", 8, {"ref": "Packed"}),
    ]
    return exe, Snapshot(Image(arch, image.image_base, image.sha256), symbols, types), addresses


def pdb_dump(path, toolchain: Toolchain, *sections):
    """llvm-pdbutil's dump of a PDB."""
    reader = executable(compiler(toolchain).parent / ("llvm-pdbutil" + EXE_SUFFIX))
    sections = sections or ("-summary", "-types", "-globals", "-publics", "-symbols", "-section-contribs")
    return run([reader, "dump", *sections, path], env=toolchain.env).stdout

