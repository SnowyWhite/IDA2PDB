"""Lower snapshot types to CodeView type records.

The native writer serializes the records produced here, in order, into the
PDB's TPI stream. Every decision about how a type is described in CodeView is
made in this module, where it can be tested without LLVM:

- A named structure or union is referenced through a forward reference record
  and defined by a separate, later record, as compilers do. Debuggers resolve
  the reference through the TPI hash of the name, so types may refer to each
  other in any order and through any cycle of pointers.
- An anonymous structure or union (IDA's `Outer::$9BFE...` types) is defined in
  place under MSVC's `<unnamed-tag>` name. When it is an unnamed member, its
  members are merged into the enclosing field list, which is how MSVC describes
  anonymous members and what lets a debugger evaluate `value.LowPart`.
- Member offsets are IDA's, so any layout IDA knows is described exactly,
  including gaps, overlapping members and packing.
- Typedefs have no type record in CodeView. A reference to a typedef is a
  reference to its target, and the name itself becomes an S_UDT symbol.
- A function type keeps its parameter types and its calling convention. On x64
  everything except __vectorcall is CV_CALL_NEAR_C, as MSVC writes it.
  __usercall and the like become the generic convention: the parameter types
  are known, their locations are not part of a CodeView type anyway.

A type reference is an integer: below 0x1000 a CodeView simple type, otherwise
0x1000 plus the position of a record in Lowering.records. Every record refers
only to records before it.
"""
from __future__ import annotations

from collections import deque
import json

from .model import BUILTINS, INTEGERS, Diagnostic, Enum, Snapshot, Struct, Typedef, TypeExpr

FIRST_RECORD = 0x1000
NOTYPE = 0x0000

# Simple type indices for the builtins: what MSVC and Clang use for the C types
# of the same size (int32 is `int`, int64 is `__int64`, char is plain `char`).
#
SIMPLE = {
    "void": 0x0003,
    "char": 0x0070, "wchar": 0x0071, "char8": 0x007c, "char16": 0x007a, "char32": 0x007b,
    "bool8": 0x0030, "bool16": 0x0031, "bool32": 0x0032, "bool64": 0x0033,
    "int8": 0x0010, "uint8": 0x0020, "int16": 0x0011, "uint16": 0x0021,
    "int32": 0x0074, "uint32": 0x0075, "int64": 0x0013, "uint64": 0x0023,
    "int128": 0x0014, "uint128": 0x0024,
    "float16": 0x0046, "float32": 0x0040, "float64": 0x0041, "float80": 0x0042, "float128": 0x0043,
}
assert SIMPLE.keys() == BUILTINS.keys()

# A pointer to a simple type is itself a simple type, with the pointer's mode in
# bits 8 to 11 of the index.
#
SIMPLE_MODE_MASK = 0x0f00
NEAR_POINTER32 = 0x0400
NEAR_POINTER64 = 0x0600

# Array index types, as MSVC writes them: unsigned long on x86, unsigned
# __int64 on x64.
#
ARRAY_INDEX = {"x86": 0x0022, "x64": 0x0023}

# CV_call_e.
#
NEAR_C = 0x00
NEAR_PASCAL = 0x02
NEAR_FAST = 0x04
NEAR_STDCALL = 0x07
THISCALL = 0x0b
GENERIC = 0x0d
NEAR_VECTOR = 0x18
SWIFT = 0x19

X86_CONVENTIONS = {
    "cdecl": NEAR_C, "unknown": NEAR_C, "stdcall": NEAR_STDCALL, "pascal": NEAR_PASCAL,
    "fastcall": NEAR_FAST, "thiscall": THISCALL, "vectorcall": NEAR_VECTOR, "swift": SWIFT,
    "usercall": GENERIC, "userpurge": GENERIC, "golang": GENERIC,
}
X64_CONVENTIONS = {
    **{cc: NEAR_C for cc in X86_CONVENTIONS},
    "vectorcall": NEAR_VECTOR, "swift": SWIFT, "usercall": GENERIC, "userpurge": GENERIC, "golang": GENERIC,
}

UNNAMED = "<unnamed-tag>"
MAX_MEMBER_COUNT = 0xffff


class Lowering:
    """Builds the type records for one snapshot.

    Call index() for every type a symbol needs, define_all() for the
    snapshot's other types, typedefs() for the S_UDT symbols, then finish()
    to emit the deferred structure definitions.
    """

    def __init__(self, snapshot: Snapshot):
        self.types = snapshot.types
        self.arch = snapshot.image.arch
        self.pointer_size = snapshot.image.pointer_size
        self.conventions = X64_CONVENTIONS if self.arch == "x64" else X86_CONVENTIONS
        self.records: list[dict] = []
        self.diagnostics: list[Diagnostic] = []
        self._dedup: dict[str, int] = {}
        self._defined: dict[str, int] = {}     # complete records of anonymous types and enums
        self._pending: deque[str] = deque()    # named structures still to be defined
        self._scheduled: set[str] = set()
        self._building: set[str] = set()       # anonymous structures being defined
        # Names already diagnosed, including types the collector could not find.
        self._reported: set[str] = {d.symbol for d in snapshot.diagnostics if d.code == "type_unavailable"}
        self._resolving: set[str] = set()       # typedefs being resolved, against cycles

    # Records.
    #
    def _add(self, record: dict) -> int:
        # Identical records (the same pointer type, written for every member that
        # uses it) are written once.
        key = json.dumps(record, sort_keys=True)
        index = self._dedup.get(key)
        if index is None:
            index = FIRST_RECORD + len(self.records)
            self.records.append(record)
            self._dedup[key] = index
        return index

    def _diagnose(self, code, message, subject=""):
        self.diagnostics.append(Diagnostic(code, message, subject))

    # Typedef resolution.
    #
    def resolve(self, expr: TypeExpr) -> TypeExpr:
        """The expression with typedef references followed to what they name."""
        seen = set()
        while isinstance(expr, dict) and "ref" in expr and isinstance(self.types.get(expr["ref"]), Typedef):
            if expr["ref"] in seen:
                return "void"  # a cycle; index() reports it
            seen.add(expr["ref"])
            expr = self.types[expr["ref"]].type
        return expr

    def is_function(self, expr: TypeExpr) -> bool:
        target = self.resolve(expr)
        return isinstance(target, dict) and "function" in target

    # Sizes.
    #
    def size(self, expr: TypeExpr) -> int:
        """The size of an object of this type, 0 when unknown."""
        expr = self.resolve(expr)
        if isinstance(expr, str):
            return BUILTINS[expr]
        if "ref" in expr:
            definition = self.types.get(expr["ref"])
            if isinstance(definition, Struct):
                return definition.size
            if isinstance(definition, Enum):
                return INTEGERS[definition.underlying]
            return 0
        if "pointer" in expr:
            return expr.get("size", self.pointer_size)
        if "array" in expr:
            return expr["count"] * self.size(expr["array"])
        if "function" in expr:
            return 0
        return self.size(expr.get("const", expr.get("volatile")))

    # Type indices.
    #
    def index(self, expr: TypeExpr) -> int:
        if isinstance(expr, str):
            return SIMPLE[expr]
        if "ref" in expr:
            return self._named(expr["ref"])
        if "pointer" in expr:
            return self._pointer(expr, False, False)
        if "array" in expr:
            element = self.index(expr["array"])
            size = expr["count"] * self.size(expr["array"])
            if size >= 1 << 64:
                self._diagnose("member_skipped", f"An array of {size} bytes is too large for CodeView; its "
                                                 "size is given as 0")
                size = 0
            return self._add({"leaf": "array", "element": element, "index": ARRAY_INDEX[self.arch],
                              "size": size})
        if "function" in expr:
            return self._procedure(expr["function"])

        const = volatile = False
        while isinstance(expr, dict) and ("const" in expr or "volatile" in expr):
            const = const or "const" in expr
            volatile = volatile or "volatile" in expr
            expr = expr.get("const", expr.get("volatile"))

        # A qualified pointer carries its qualifiers itself, also when it is
        # spelled through a typedef (`const HANDLE`).
        target = self.resolve(expr)
        if isinstance(target, dict) and "pointer" in target:
            return self._pointer(target, const, volatile)
        return self._add({"leaf": "modifier", "type": self.index(expr), "const": const, "volatile": volatile})

    def _pointer(self, expr, const, volatile):
        size = expr.get("size", self.pointer_size)
        referent = self.index(expr["pointer"])
        if referent < FIRST_RECORD and referent != NOTYPE and not referent & SIMPLE_MODE_MASK \
                and not const and not volatile:
            return referent | (NEAR_POINTER64 if size == 8 else NEAR_POINTER32)
        return self._add({"leaf": "pointer", "referent": referent, "size": size,
                          "const": const, "volatile": volatile})

    def _procedure(self, function):
        result = self.index(function["return"])
        params = [self.index(p) for p in function["params"]]
        if function.get("varargs", False):
            # CodeView marks a variadic function with a trailing T_NOTYPE.
            params.append(NOTYPE)
        args = self._add({"leaf": "arglist", "args": params})
        return self._add({"leaf": "procedure", "return": result, "args": args, "count": len(params),
                          "cc": self.conventions[function.get("cc", "cdecl")]})

    def _named(self, name):
        definition = self.types.get(name)
        if definition is None:
            if name not in self._reported:
                self._reported.add(name)
                self._diagnose("type_missing", f"Type {name!r} is referenced but not defined in the snapshot; "
                                               "it is declared without members", name)
            return self._add({"leaf": "struct", "name": name, "forward": True})
        if isinstance(definition, Typedef):
            if name in self._resolving:
                if name not in self._reported:
                    self._reported.add(name)
                    self._diagnose("typedef_cycle", f"Typedef {name!r} refers to itself", name)
                return NOTYPE
            self._resolving.add(name)
            try:
                return self.index(definition.type)
            finally:
                self._resolving.discard(name)
        if isinstance(definition, Enum):
            return self._enum(name, definition)
        if definition.anonymous:
            return self._define(name, definition)
        if definition.members is not None and name not in self._scheduled:
            self._scheduled.add(name)
            self._pending.append(name)
        return self._add({"leaf": definition.kind, "name": name, "forward": True})

    # Definitions.
    #
    def _enum(self, name, definition):
        index = self._defined.get(name)
        if index is None:
            fields = [{"kind": "enumerator", "name": n, "value": v} for n, v in definition.values.items()]
            fieldlist = self._add({"leaf": "fieldlist", "fields": fields})
            index = self._add({"leaf": "enum", "name": UNNAMED if definition.anonymous else name,
                               "underlying": SIMPLE[definition.underlying], "fields": fieldlist,
                               "count": self._count(name, fields)})
            self._defined[name] = index
        return index

    def _define(self, name, definition: Struct):
        """The complete record of a structure, emitted now."""
        index = self._defined.get(name)
        if index is not None:
            return index
        if definition.members is None or name in self._building:
            # A declared-only anonymous type, or one that contains itself
            # (which C cannot spell): keep a reference rather than recurse.
            return self._add({"leaf": definition.kind, "name": UNNAMED if definition.anonymous else name,
                              "forward": True})
        self._building.add(name)
        try:
            fields = []
            self._fields(name, definition, 0, fields)
        finally:
            self._building.discard(name)
        fieldlist = self._add({"leaf": "fieldlist", "fields": fields})
        index = self._add({"leaf": definition.kind, "name": UNNAMED if definition.anonymous else name,
                           "forward": False, "fields": fieldlist, "count": self._count(name, fields),
                           "size": definition.size})
        self._defined[name] = index
        return index

    def _count(self, name, fields):
        # A record's count has 16 bits; the field list itself keeps every field.
        if len(fields) > MAX_MEMBER_COUNT:
            self._diagnose("member_count", f"{name} has {len(fields)} members; its record can only count "
                                           f"{MAX_MEMBER_COUNT}", name)
        return min(len(fields), MAX_MEMBER_COUNT)

    def _fields(self, owner, definition: Struct, base, fields):
        for member in definition.members:
            if member.base:
                fields.append({"kind": "base", "type": self.index(member.type), "offset": base + member.offset})
            elif member.is_bitfield:
                self._bitfield(owner, member, base, fields)
            elif (nested := self._anonymous_member(member)) is not None:
                if nested[0] in self._building:
                    self._diagnose("member_skipped", f"{owner}: anonymous member contains itself", owner)
                    continue
                self._building.add(nested[0])
                try:
                    self._fields(owner, nested[1], base + member.offset, fields)
                finally:
                    self._building.discard(nested[0])
            else:
                fields.append({"kind": "member", "name": member.name, "type": self.index(member.type),
                               "offset": base + member.offset})

    def _anonymous_member(self, member):
        """(name, definition) when the member is an unnamed anonymous structure or union."""
        if member.name or not isinstance(member.type, dict) or "ref" not in member.type:
            return None
        definition = self.types.get(member.type["ref"])
        if isinstance(definition, Struct) and definition.anonymous and definition.members is not None:
            return member.type["ref"], definition
        return None

    def _bitfield(self, owner, member, base, fields):
        # CodeView places a bitfield in a storage unit of its type's size at a
        # byte offset, and counts its bits from there. Prefer the unit at a
        # multiple of its size, where MSVC puts it; any unit that holds all the
        # bits describes them correctly.
        unit = INTEGERS[member.type]
        absolute = base * 8 + member.bit_offset
        byte = absolute // 8
        start = byte - byte % unit
        if absolute - start * 8 + member.bit_width > unit * 8:
            start = byte
        position = absolute - start * 8
        if position + member.bit_width > unit * 8:
            self._diagnose("member_skipped", f"{owner}.{member.name}: a {member.bit_width}-bit field does not fit "
                                             f"a {unit}-byte storage unit", owner)
            return
        bitfield = self._add({"leaf": "bitfield", "type": SIMPLE[member.type], "width": member.bit_width,
                              "position": position})
        fields.append({"kind": "member", "name": member.name, "type": bitfield, "offset": start})

    # Results.
    #
    def typedefs(self) -> list[dict]:
        """The S_UDT symbols: every typedef with the type it names."""
        out = []
        for name, definition in self.types.items():
            if isinstance(definition, Typedef):
                index = self._named(name)
                if index != NOTYPE:
                    out.append({"name": name, "type": index})
        return out

    def define_all(self):
        """Emit every structure, union and enumeration of the snapshot, used or not."""
        for name, definition in self.types.items():
            if not isinstance(definition, Typedef):
                self._named(name)

    def finish(self):
        """Emit the definitions that forward references are waiting for."""
        while self._pending:
            name = self._pending.popleft()
            self._define(name, self.types[name])
