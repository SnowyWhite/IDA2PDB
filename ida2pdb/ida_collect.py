"""Take a snapshot of an IDA database. This is the only module that imports IDA.

    collect_current(options)        the database open in this process (IDA's
                                    main thread, or an idalib script)
    collect_database(path, options) a closed .i64/.idb, opened through idalib in
                                    a private copy and closed without saving

Collection reads names and types only; it never edits the database and needs
no decompiler. Types are recorded as IDA models them (model.py), not printed as
C: IDA's printed declarations are not always valid C++ (nested anonymous types
print as `struct Outer::$9BFE... {...}`, wchar_t can be a typedef), and the
builder needs layouts, not source.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

from .errors import ExportError
from .model import BUILTINS, Diagnostic, Enum, Image, Member, Snapshot, Struct, Symbol, Typedef

# C++ spells these types with keywords; IDA may hold them as typedefs.
#
KEYWORD_TYPES = {"wchar_t": "wchar", "char8_t": "char8", "char16_t": "char16", "char32_t": "char32"}


@dataclass
class CollectOptions:
    names: str = "user"         # "user": names someone gave; "all": IDA's whole name list
    types: str = "referenced"   # "none", "referenced" (what the symbols use), or "all" local types
    inferred_types: bool = False  # also types IDA guessed, not only those set explicitly
    include: str = ""           # regular expression a name must match
    exclude: str = ""           # regular expression a name must not match
    segments: list[str] = field(default_factory=list)  # IDA segment names to take symbols from


def collect_current(options: CollectOptions | None = None, *, cancelled=lambda: False) -> Snapshot:
    """Snapshot the current database.

    Call only from IDA's main thread (or idalib's initializing thread). Waits
    for autoanalysis first; cancelled() is polled and aborts the collection.
    """
    import ida_auto
    import ida_bytes
    import ida_funcs
    import ida_ida
    import ida_kernwin
    import ida_nalt
    import ida_segment
    import ida_typeinf
    import idautils

    options = options or CollectOptions()
    if options.names not in ("user", "all") or options.types not in ("none", "referenced", "all"):
        raise ExportError("invalid name/type collection policy")
    try:
        include = re.compile(options.include) if options.include else None
        exclude = re.compile(options.exclude) if options.exclude else None
    except re.error as e:
        raise ExportError(f"invalid symbol filter: {e}") from e
    if ida_ida.inf_get_filetype() != ida_ida.f_PE or ida_ida.inf_get_procname() != "metapc":
        raise ExportError("the current database must be an x86 or x64 PE image")
    if not ida_auto.auto_wait() or cancelled():
        raise ExportError("export cancelled while waiting for IDA analysis")

    arch = "x64" if ida_ida.inf_is_64bit() else "x86"
    base = ida_nalt.get_imagebase()
    digest = ida_nalt.retrieve_input_file_sha256()
    snapshot = Snapshot(Image(arch, base, digest.hex() if digest and len(digest) == 32 else ""), [],
                        producer=f"ida2pdb; IDA {ida_kernwin.get_kernel_version()}")
    types = _TypeCollector(ida_typeinf, snapshot)

    for ea, name in idautils.Names():
        if cancelled():
            raise ExportError("export cancelled")
        flags = ida_bytes.get_flags(ea)
        if options.names == "user" and not ida_bytes.has_user_name(flags):
            continue
        if (include and not include.search(name)) or (exclude and exclude.search(name)):
            continue
        segment = ida_segment.getseg(ea)
        if options.segments and (segment is None
                                 or ida_segment.get_segm_name(segment) not in options.segments):
            continue
        rva = ea - base
        if not 0 <= rva < (1 << 32):
            snapshot.diagnostics.append(Diagnostic("outside_image", "The address cannot be expressed as an RVA "
                                                   "of the image", name))
            continue

        function = ida_funcs.get_func(ea)
        if function is not None and function.start_ea == ea:
            symbol = Symbol(name, rva, "function", function.end_ea - ea)
        elif ida_bytes.is_data(flags):
            symbol = Symbol(name, rva, "data", ida_bytes.get_item_size(ea))
        else:
            symbol = Symbol(name, rva, "label", ida_bytes.get_item_size(ea))

        tif = ida_typeinf.tinfo_t()
        if (options.types != "none" and symbol.kind != "label"
                and (options.inferred_types or ida_nalt.is_userti(ea))
                and ida_nalt.get_tinfo(tif, ea)):
            if symbol.kind == "function" and not tif.is_func():
                snapshot.diagnostics.append(Diagnostic("invalid_function_type", f"IDA's type for the function is "
                                                       f"not a function type: {tif.dstr()}", name))
            else:
                symbol.type = types.expression(tif)
                arguments = ida_typeinf.func_type_data_t()
                if tif.is_func() and tif.get_func_details(arguments) and any(a.name for a in arguments):
                    symbol.params = [a.name for a in arguments]
        snapshot.symbols.append(symbol)

    if options.types == "all":
        til = ida_typeinf.get_idati()
        for ordinal in range(1, ida_typeinf.get_ordinal_limit(til)):
            name = ida_typeinf.get_numbered_type_name(til, ordinal)
            if name:
                types.reference(name)
    types.collect(cancelled)

    snapshot.symbols.sort(key=lambda s: (s.rva, s.name))
    # Validate before returning: malformed IDA data must stop here.
    return snapshot.validated()


class _TypeCollector:
    """Converts tinfo_t objects into type expressions and named definitions.

    expression() handles a type's structure (pointers, arrays, functions,
    qualifiers, builtins) recursively and turns every named type it meets into
    a reference; the definitions of those names are collected afterwards by
    collect(), from a work list, so that types referring to each other (also
    through long chains) need no recursion.
    """

    def __init__(self, ida_typeinf, snapshot):
        self.ti = ida_typeinf
        self.til = ida_typeinf.get_idati()
        self.snapshot = snapshot
        self.pending = deque()
        self.seen = set()

    def diagnose(self, code, message, subject):
        self.snapshot.diagnostics.append(Diagnostic(code, message, subject))

    def reference(self, name):
        if name not in self.seen:
            self.seen.add(name)
            self.pending.append(name)
        return {"ref": name}

    # Type expressions.
    #
    def expression(self, tif, *, through_name=True):
        """A tinfo_t as a type expression.

        A named type becomes a reference, unless through_name is false, which
        describes what the name stands for instead (for a typedef's target).
        """
        expr = self._unqualified(tif, through_name)
        if tif.is_decl_volatile():
            expr = {"volatile": expr}
        if tif.is_decl_const():
            expr = {"const": expr}
        return expr

    def _unqualified(self, tif, through_name):
        name = tif.get_type_name() if through_name else None
        if name:
            # C++ spells these as keywords; IDA may hold them as typedefs.
            builtin = KEYWORD_TYPES.get(name)
            if builtin and tif.get_size() == BUILTINS[builtin]:
                return builtin
            return self.reference(name)

        if tif.is_ptr():
            pointer = {"pointer": self.expression(tif.get_pointed_object())}
            if tif.get_size() != self.snapshot.image.pointer_size:
                pointer["size"] = tif.get_size()  # __ptr32, __ptr64
            return pointer
        if tif.is_array():
            count = tif.get_array_nelems()
            return {"array": self.expression(tif.get_array_element()), "count": max(count, 0)}
        if tif.is_func():
            return {"function": self._function(tif)}
        if tif.is_udt() or tif.is_enum():
            # An unnamed structure or enumeration defined in place. IDA 9 names
            # nested anonymous types (Outer::$...), so this is rare.
            name = f"$anonymous_{len(self.seen)}"
            self.seen.add(name)
            definition = self._definition(tif, name, anonymous=True)
            if definition is not None:
                self.snapshot.types[name] = definition
                return {"ref": name}
            return "void"
        return self._builtin(tif)

    def _builtin(self, tif):
        size = tif.get_size()
        if tif.is_void():
            return "void"
        if tif.is_bool() and size in (1, 2, 4, 8):
            return f"bool{size * 8}"
        if tif.is_floating() and size in (2, 4, 8, 10, 16):
            return f"float{size * 8}"
        if tif.is_char():
            return "char"
        if (tif.is_integral() or tif.is_unknown()) and size in (1, 2, 4, 8, 16):
            # IDA's _BYTE, _DWORD, ... (unknown) are unsigned; integers whose
            # signedness IDA leaves open (__int16) are signed, as in C.
            return f"{'u' if tif.is_unsigned() or tif.is_unknown() else ''}int{size * 8}"
        # _UNKNOWN and anything without a size the debugger could show.
        return "void"

    def _function(self, tif):
        ti = self.ti
        data = ti.func_type_data_t()
        if not tif.get_func_details(data):
            return {"return": "void", "params": [], "cc": "unknown"}
        cc = data.get_explicit_cc() & ti.CM_CC_MASK
        convention = {
            ti.CM_CC_CDECL: "cdecl", ti.CM_CC_ELLIPSIS: "cdecl", ti.CM_CC_VOIDARG: "cdecl",
            ti.CM_CC_STDCALL: "stdcall", ti.CM_CC_PASCAL: "pascal", ti.CM_CC_FASTCALL: "fastcall",
            ti.CM_CC_THISCALL: "thiscall", ti.CM_CC_SWIFT: "swift", ti.CM_CC_GOLANG: "golang",
            ti.CM_CC_SPECIAL: "usercall", ti.CM_CC_SPECIALE: "usercall", ti.CM_CC_SPECIALP: "userpurge",
        }.get(cc, "unknown")
        function = {"return": self.expression(data.rettype),
                    "params": [self.expression(a.type) for a in data],
                    "cc": convention}
        if data.is_vararg_cc():
            function["varargs"] = True
        return function

    # Named definitions.
    #
    def collect(self, cancelled):
        while self.pending:
            if cancelled():
                raise ExportError("export cancelled")
            name = self.pending.popleft()
            tif = self.ti.tinfo_t()
            if not tif.get_named_type(self.til, name):
                self.diagnose("type_unavailable", f"IDA cannot find the definition of type {name!r}", name)
                continue
            definition = self._definition(tif, name)
            if definition is not None:
                self.snapshot.types[name] = definition

    def _definition(self, tif, name, anonymous=False):
        ti = self.ti
        if tif.is_typedef():
            # `typedef A B` names A; `typedef void *HANDLE` describes a type.
            target = tif.get_next_type_name()
            if not target:
                return Typedef(self.expression(tif, through_name=False))
            if target in KEYWORD_TYPES and tif.get_size() == BUILTINS[KEYWORD_TYPES[target]]:
                expr = KEYWORD_TYPES[target]  # typedef wchar_t WCHAR
            else:
                expr = self.reference(target)
            if tif.is_decl_volatile():
                expr = {"volatile": expr}
            if tif.is_decl_const():
                expr = {"const": expr}
            return Typedef(expr)

        # IDA names anonymous types $HASH (nested ones Outer::$HASH). Only the
        # name decides: a named type that IDA flags anonymous (typedef struct
        # {...} FOO, stored as FOO) must keep its name.
        anonymous = anonymous or name.startswith("$") or "::$" in name
        if tif.is_enum():
            data = ti.enum_type_data_t()
            if not tif.get_enum_details(data):
                return Enum("int32", anonymous=anonymous)  # declared only: no values
            width = tif.get_enum_width() or data.calc_nbytes() or 4
            if width not in (1, 2, 4, 8):
                self.diagnose("type_unavailable", f"Enumeration {name!r} has an unsupported width of {width} bytes",
                              name)
                return None
            signed = tif.get_sign() != ti.type_unsigned
            bits = width * 8
            values = {}
            for member in data:
                value = member.value & ((1 << bits) - 1)
                if signed and value >= 1 << (bits - 1):
                    value -= 1 << bits
                values[member.name] = value
            return Enum(f"{'' if signed else 'u'}int{bits}", values, anonymous)

        if tif.is_udt():
            kind = "union" if tif.is_union() else "struct"
            data = ti.udt_type_data_t()
            size = tif.get_size()
            if not tif.get_udt_details(data) or size == ti.BADSIZE:
                return Struct(kind, anonymous=anonymous)  # declared only
            members = []
            for m in data:
                # Gaps and methods are not storage; a zero-width bitfield only
                # forces alignment, which the offsets already reflect.
                if m.is_gap() or m.is_method() or m.is_zero_bitfield():
                    continue
                if m.type.is_bitfield():
                    bitfield = ti.bitfield_type_data_t()
                    m.type.get_bitfield_details(bitfield)
                    unit = f"{'u' if bitfield.is_unsigned else ''}int{bitfield.nbytes * 8}"
                    members.append(Member(m.name, unit, bit_offset=m.offset, bit_width=bitfield.width))
                elif m.offset % 8:
                    self.diagnose("member_skipped", f"{name}.{m.name} starts inside a byte", name)
                elif m.is_baseclass() and m.type.get_type_name():
                    members.append(Member("", self.expression(m.type), m.offset // 8, base=True))
                else:
                    members.append(Member(m.name, self.expression(m.type), m.offset // 8))
            return Struct(kind, size, members, anonymous)

        if tif.is_forward_decl():
            return Struct("union" if tif.is_forward_union() else "struct", anonymous=anonymous)
        # A named type that is neither a typedef nor a definition: describe
        # what it stands for.
        return Typedef(self.expression(tif, through_name=False))


def collect_database(path, options: CollectOptions | None = None) -> Snapshot:
    """Collect a packed .i64/.idb through idalib, in a private copy.

    idalib may leave unpacked database files behind even on a non-saving
    close. Working on a copy keeps the input untouched and leaves nothing stale
    next to it. IDA user plugins are disabled for the collection.
    """
    path = Path(path).resolve()
    if not path.is_file() or path.suffix.lower() not in (".i64", ".idb"):
        raise ExportError("collect requires an existing packed .i64 or .idb database")
    for suffix in (".id0", ".id1", ".id2", ".nam", ".til"):
        if path.with_suffix(suffix).exists():
            raise ExportError(f"{path.with_suffix(suffix)} exists: the database is open or was not packed. "
                              "Close it in IDA (packing it) or export from IDA with the plugin")
    with tempfile.TemporaryDirectory(prefix="ida2pdb-ida-") as directory:
        tmp = Path(directory)
        copy = tmp / path.name
        shutil.copy2(path, copy)
        userdir = tmp / "idausr"
        (userdir / "plugins").mkdir(parents=True)
        old_user = os.environ.get("IDAUSR")
        os.environ["IDAUSR"] = str(userdir)
        try:
            python_paths = list(sys.path)
            try:
                import idapro
            except ImportError as e:
                raise ExportError("idalib is unavailable: run with the Python that IDA's idalib is set up for "
                                  "(py-activate-idalib.py), or export a snapshot from the IDA plugin") from e
            finally:
                # Initializing IDAPython can replace the host's import path.
                # Keep its new entries and restore the application's.
                for entry in reversed(python_paths):
                    if entry not in sys.path:
                        sys.path.insert(0, entry)
            if rc := idapro.open_database(str(copy), False):
                raise ExportError(f"idalib could not open the database (error {rc})")
            try:
                return collect_current(options)
            finally:
                idapro.close_database(save=False)
        finally:
            if old_user is None:
                os.environ.pop("IDAUSR", None)
            else:
                os.environ["IDAUSR"] = old_user
