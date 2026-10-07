"""The snapshot: everything the PDB builder needs from an IDA database.

A snapshot is plain JSON (docs/snapshot-format.md describes it). The collector
produces one inside IDA; everything after that reads only the snapshot, so a PDB
can be rebuilt later, elsewhere, without IDA.

Symbols and type definitions are dataclasses. Type expressions (the type of a
symbol, a member or a typedef) stay plain JSON values, since they are small
trees that the code only ever walks:

    "int32"                                   a builtin (see BUILTINS)
    {"ref": "Name"}                           a named type in Snapshot.types
    {"pointer": T}                            {"pointer": T, "size": 4} for __ptr32
    {"array": T, "count": 3}
    {"function": {"return": T, "params": [T, ...],
                  "cc": "cdecl", "varargs": false}}
    {"const": T}, {"volatile": T}

Loading and saving validate the complete contract, so malformed data stops here
rather than in the native writer.
"""
from __future__ import annotations

from dataclasses import MISSING, dataclass, field
import json
from pathlib import Path
import re
from typing import Any, Union

from .errors import ExportError
from .util import write_json

FORMAT = "ida2pdb"

ARCHES = ("x86", "x64")
SYMBOL_KINDS = ("function", "data", "label")

# Builtin type names and their sizes in bytes. They name machine types rather
# than C spellings: IDA's `__int16`, `short` and `_WORD` all describe a 16-bit
# integer, and a debugger needs nothing more.
#
BUILTINS = {
    "void": 0,
    "char": 1, "wchar": 2, "char8": 1, "char16": 2, "char32": 4,
    "bool8": 1, "bool16": 2, "bool32": 4, "bool64": 8,
    "int8": 1, "uint8": 1, "int16": 2, "uint16": 2, "int32": 4, "uint32": 4,
    "int64": 8, "uint64": 8, "int128": 16, "uint128": 16,
    "float16": 2, "float32": 4, "float64": 8, "float80": 10, "float128": 16,
}

INTEGERS = {name: size for name, size in BUILTINS.items() if re.fullmatch(r"u?int\d+", name)}

# The integers a bitfield's storage unit or an enumeration can have: CodeView
# encodes bit positions and enumerator values in at most 64 bits.
#
UNIT_INTEGERS = {name: size for name, size in INTEGERS.items() if size <= 8}

CALLING_CONVENTIONS = ("cdecl", "stdcall", "pascal", "fastcall", "thiscall", "vectorcall",
                       "usercall", "userpurge", "golang", "swift", "unknown")

# A CodeView record holds at most 0xFF00 bytes, and a name shares its record
# with a fixed header. This bound leaves room for the largest header.
#
MAX_NAME_BYTES = 60000

TypeExpr = Union[str, dict]


def _object(value, path, allowed, required=()):
    if not isinstance(value, dict):
        raise ExportError(f"{path}: expected an object")
    unknown = value.keys() - set(allowed)
    missing = set(required) - value.keys()
    if unknown or missing:
        raise ExportError(f"{path}: unknown fields {sorted(unknown)}, missing fields {sorted(missing)}")
    return value


def _text(value, path, *, nonempty=False, name=False):
    if not isinstance(value, str) or "\0" in value or (nonempty and not value):
        raise ExportError(f"{path}: expected {'nonempty ' if nonempty else ''}text without NUL")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as e:
        raise ExportError(f"{path}: invalid Unicode") from e
    if name and len(encoded) > MAX_NAME_BYTES:
        raise ExportError(f"{path}: too long for a CodeView record")
    return value


def _uint(value, path, bits=32):
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise ExportError(f"{path}: expected an unsigned {bits}-bit integer")
    return value


def _bool(value, path):
    if type(value) is not bool:
        raise ExportError(f"{path}: expected a boolean")
    return value


def _list(value, path):
    if not isinstance(value, list):
        raise ExportError(f"{path}: expected an array")
    return value


def check_type(expr, path) -> TypeExpr:
    """Validate a type expression and return it unchanged."""
    if isinstance(expr, str):
        if expr not in BUILTINS:
            raise ExportError(f"{path}: unknown builtin type {expr!r}")
        return expr
    kinds = {"ref", "pointer", "array", "function", "const", "volatile"}
    if not isinstance(expr, dict) or len(expr.keys() & kinds) != 1:
        raise ExportError(f"{path}: expected a type expression")
    if "ref" in expr:
        _object(expr, path, ("ref",))
        _text(expr["ref"], path + ".ref", nonempty=True, name=True)
    elif "pointer" in expr:
        _object(expr, path, ("pointer", "size"))
        if type(expr.get("size", 4)) is not int or expr.get("size", 4) not in (4, 8):
            raise ExportError(f"{path}.size: expected 4 or 8")
        check_type(expr["pointer"], path + ".pointer")
    elif "array" in expr:
        _object(expr, path, ("array", "count"), ("count",))
        _uint(expr["count"], path + ".count")
        check_type(expr["array"], path + ".array")
    elif "function" in expr:
        _object(expr, path, ("function",))
        function = _object(expr["function"], path + ".function", ("return", "params", "cc", "varargs"),
                           ("return", "params"))
        check_type(function["return"], path + ".function.return")
        for i, param in enumerate(_list(function["params"], path + ".function.params")):
            check_type(param, f"{path}.function.params[{i}]")
        if function.get("cc", "cdecl") not in CALLING_CONVENTIONS:
            raise ExportError(f"{path}.function.cc: unknown calling convention")
        _bool(function.get("varargs", False), path + ".function.varargs")
    else:
        key = "const" if "const" in expr else "volatile"
        _object(expr, path, (key,))
        check_type(expr[key], f"{path}.{key}")
    return expr


@dataclass
class Image:
    """The executable IDA analyzed, as far as the snapshot can identify it."""
    arch: str
    image_base: int
    input_sha256: str = ""

    @classmethod
    def parse(cls, d):
        _object(d, "image", cls.__dataclass_fields__, ("arch", "image_base"))
        if d["arch"] not in ARCHES:
            raise ExportError("image.arch: expected x86 or x64")
        _uint(d["image_base"], "image.image_base", 64)
        digest = _text(d.get("input_sha256", ""), "image.input_sha256")
        if digest and not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ExportError("image.input_sha256: expected a lowercase SHA-256 digest")
        return cls(**d)

    @property
    def pointer_size(self):
        return 8 if self.arch == "x64" else 4


@dataclass
class Symbol:
    """A named address.

    `size` is the extent of a function's entry chunk, or IDA's item size for
    anything else. `params` names a function's parameters, in the order of its
    type's parameters; an empty name is an unnamed parameter.
    """
    name: str
    rva: int
    kind: str
    size: int = 0
    type: TypeExpr | None = None
    params: list[str] = field(default_factory=list)

    @classmethod
    def parse(cls, d, path):
        _object(d, path, cls.__dataclass_fields__, ("name", "rva", "kind"))
        _text(d["name"], path + ".name", nonempty=True, name=True)
        _uint(d["rva"], path + ".rva")
        _uint(d.get("size", 0), path + ".size")
        if d["kind"] not in SYMBOL_KINDS:
            raise ExportError(f"{path}.kind: expected function, data, or label")
        kind = d["kind"]
        if d.get("type") is not None:
            if kind == "label":
                raise ExportError(f"{path}.type: labels cannot have types")
            check_type(d["type"], path + ".type")
        params = _list(d.get("params", []), path + ".params")
        for i, param in enumerate(params):
            _text(param, f"{path}.params[{i}]", name=True)
        if params and kind != "function":
            raise ExportError(f"{path}.params: only functions have parameters")
        return cls(d["name"], d["rva"], kind, d.get("size", 0), d.get("type"), list(params))


@dataclass
class Member:
    """A structure or union member.

    Ordinary members have a byte `offset`. Bitfields have `bit_offset` and
    `bit_width` instead, both in bits from the start of the enclosing type, and
    `type` is the integer type of their storage unit. A base class is a member
    with `base` set; an unnamed member of an anonymous type is IDA's spelling
    of an anonymous struct or union.
    """
    name: str
    type: TypeExpr
    offset: int = 0
    bit_offset: int | None = None
    bit_width: int | None = None
    base: bool = False

    @property
    def is_bitfield(self):
        return self.bit_width is not None

    @classmethod
    def parse(cls, d, path):
        _object(d, path, cls.__dataclass_fields__, ("name", "type"))
        _text(d["name"], path + ".name", name=True)
        check_type(d["type"], path + ".type")
        bitfield = "bit_offset" in d or "bit_width" in d
        if bitfield:
            if "offset" in d or d.get("base", False) or not ("bit_offset" in d and "bit_width" in d):
                raise ExportError(f"{path}: a bitfield has bit_offset and bit_width instead of offset")
            _uint(d["bit_offset"], path + ".bit_offset")
            if type(d["bit_width"]) is not int or not 1 <= d["bit_width"] <= 64:
                raise ExportError(f"{path}.bit_width: expected 1 to 64")
            if not isinstance(d["type"], str) or d["type"] not in UNIT_INTEGERS:
                raise ExportError(f"{path}.type: a bitfield's storage unit must be an integer builtin of "
                                  "at most 64 bits")
            if d["bit_width"] > UNIT_INTEGERS[d["type"]] * 8:
                raise ExportError(f"{path}.bit_width: wider than its storage unit")
        else:
            _uint(d.get("offset", 0), path + ".offset")
        _bool(d.get("base", False), path + ".base")
        if d.get("base", False) and (not isinstance(d["type"], dict) or "ref" not in d["type"]):
            raise ExportError(f"{path}.type: a base class must be a named type")
        return cls(**d)


@dataclass
class Struct:
    """A structure or union. `members` is None for a type IDA only declares."""
    kind: str
    size: int = 0
    members: list[Member] | None = None
    anonymous: bool = False

    @classmethod
    def parse(cls, d, path):
        _object(d, path, cls.__dataclass_fields__, ("kind",))
        _uint(d.get("size", 0), path + ".size")
        _bool(d.get("anonymous", False), path + ".anonymous")
        members = d.get("members")
        if members is not None:
            members = [Member.parse(m, f"{path}.members[{i}]")
                       for i, m in enumerate(_list(members, path + ".members"))]
        elif d.get("size", 0):
            raise ExportError(f"{path}: a declared-only type has no size")
        return cls(d["kind"], d.get("size", 0), members, d.get("anonymous", False))


@dataclass
class Enum:
    """An enumeration; `values` keeps IDA's member order."""
    underlying: str
    values: dict[str, int] = field(default_factory=dict)
    anonymous: bool = False
    kind: str = "enum"

    @classmethod
    def parse(cls, d, path):
        _object(d, path, cls.__dataclass_fields__, ("kind", "underlying"))
        if not isinstance(d["underlying"], str) or d["underlying"] not in UNIT_INTEGERS:
            raise ExportError(f"{path}.underlying: expected an integer builtin of at most 64 bits")
        bits = INTEGERS[d["underlying"]] * 8
        low, high = (0, 1 << bits) if d["underlying"].startswith("u") else (-(1 << (bits - 1)), 1 << (bits - 1))
        values = d.get("values", {})
        if not isinstance(values, dict):
            raise ExportError(f"{path}.values: expected an object")
        for name, value in values.items():
            _text(name, path + ".values key", nonempty=True, name=True)
            if type(value) is not int or not low <= value < high:
                raise ExportError(f"{path}.values.{name}: outside the range of {d['underlying']}")
        _bool(d.get("anonymous", False), path + ".anonymous")
        return cls(d["underlying"], dict(values), d.get("anonymous", False))


@dataclass
class Typedef:
    """Another name for a type."""
    type: TypeExpr
    kind: str = "typedef"

    @classmethod
    def parse(cls, d, path):
        _object(d, path, cls.__dataclass_fields__, ("kind", "type"))
        return cls(check_type(d["type"], path + ".type"))


Definition = Union[Struct, Enum, Typedef]


def parse_definition(d, path) -> Definition:
    kind = d.get("kind") if isinstance(d, dict) else None
    if kind in ("struct", "union"):
        return Struct.parse(d, path)
    if kind == "enum":
        return Enum.parse(d, path)
    if kind == "typedef":
        return Typedef.parse(d, path)
    raise ExportError(f"{path}.kind: expected struct, union, enum, or typedef")


@dataclass
class Diagnostic:
    """Something the export could not represent; `symbol` names what it affects."""
    code: str
    message: str
    symbol: str = ""

    @classmethod
    def parse(cls, d, path):
        _object(d, path, cls.__dataclass_fields__, ("code", "message"))
        for k in d:
            _text(d[k], path + "." + k, nonempty=k != "symbol")
        return cls(**d)


@dataclass
class Snapshot:
    """Symbols and the types they use, for one image. Symbols are unique by
    (name, rva); types are keyed by their IDA name."""
    image: Image
    symbols: list[Symbol]
    types: dict[str, Definition] = field(default_factory=dict)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    producer: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"format": FORMAT, "image": _plain(self.image),
                "symbols": [_plain(s) for s in self.symbols],
                "types": {name: _plain(d) for name, d in self.types.items()},
                "diagnostics": [_plain(d) for d in self.diagnostics], "producer": self.producer}

    @classmethod
    def from_dict(cls, d):
        _object(d, "snapshot", ("format", "image", "symbols", "types", "diagnostics", "producer"),
                ("format", "image", "symbols"))
        if d["format"] != FORMAT:
            raise ExportError(f"not a snapshot: format is not {FORMAT!r}")
        symbols = [Symbol.parse(v, f"symbols[{i}]") for i, v in enumerate(_list(d["symbols"], "symbols"))]
        seen = set()
        for s in symbols:
            if (s.name, s.rva) in seen:
                raise ExportError(f"duplicate symbol {s.name!r} at RVA {s.rva:#x}")
            seen.add((s.name, s.rva))
        types = d.get("types", {})
        if not isinstance(types, dict):
            raise ExportError("types: expected an object")
        definitions = {}
        for name, definition in types.items():
            _text(name, "types key", nonempty=True, name=True)
            definitions[name] = parse_definition(definition, f"types[{name!r}]")
        diagnostics = [Diagnostic.parse(v, f"diagnostics[{i}]")
                       for i, v in enumerate(_list(d.get("diagnostics", []), "diagnostics"))]
        return cls(Image.parse(d["image"]), symbols, definitions, diagnostics,
                   _text(d.get("producer", ""), "producer"))

    @classmethod
    def load(cls, path):
        try:
            with Path(path).open(encoding="utf-8") as f:
                return cls.from_dict(json.load(f))
        except (OSError, ValueError) as e:
            raise ExportError(f"cannot read snapshot {path}: {e}") from e

    def save(self, path):
        # Validate programmatic callers too, before replacing an existing file.
        data = self.to_dict()
        self.from_dict(json.loads(json.dumps(data)))
        write_json(path, data)

    def validated(self):
        """A validated deep copy, so that the caller's object stays untouched."""
        return self.from_dict(json.loads(json.dumps(self.to_dict())))


def _plain(value):
    """A dataclass as JSON, leaving out optional fields that hold their default.

    `kind` is always written: it is what tells the definitions apart.
    """
    out = {}
    for name, f in value.__dataclass_fields__.items():
        v = getattr(value, name)
        if f.default is not MISSING:
            optional, default = True, f.default
        elif f.default_factory is not MISSING:
            optional, default = True, f.default_factory()
        else:
            optional, default = False, None
        if name == "kind" or not optional or v != default:
            if isinstance(v, list):
                v = [_plain(x) if hasattr(x, "__dataclass_fields__") else x for x in v]
            out[name] = v
    return out
