# Snapshot format

A snapshot is the complete input of a PDB build: the image's identity, its symbols, and the types they reference.  
It is a UTF-8 JSON document written by the plugin and `ida2pdb collect`, and read by `ida2pdb build`.  
Third-party tools may produce it as well.

`ida2pdb.model` implements the schema.  
Loading and saving validate it fully: unknown or missing fields, malformed strings and out-of-range integers are rejected.

## Example

```json
{
  "format": "ida2pdb",
  "image": {"arch": "x64", "image_base": 5368709120, "input_sha256": ""},
  "symbols": [
    {"name": "Player_Spawn", "rva": 4096, "kind": "function", "size": 80,
     "type": {"function": {"return": "void",
                           "params": [{"pointer": {"ref": "Player"}}, "int32"],
                           "cc": "fastcall"}},
     "params": ["player", "team"]},
    {"name": "g_players", "rva": 8192, "kind": "data", "size": 96,
     "type": {"array": {"ref": "Player"}, "count": 2}},
    {"name": "loc_1234", "rva": 4660, "kind": "label"}
  ],
  "types": {
    "Player": {"kind": "struct", "size": 48, "members": [
      {"name": "name", "type": {"pointer": "char"}},
      {"name": "health", "type": "int32", "offset": 8},
      {"name": "team", "type": {"ref": "Team"}, "offset": 12},
      {"name": "alive", "type": "uint32", "bit_offset": 128, "bit_width": 1},
      {"name": "", "type": {"ref": "Player::$position"}, "offset": 24}
    ]},
    "Player::$position": {"kind": "union", "size": 24, "anonymous": true,
                          "members": [
      {"name": "origin", "type": {"array": "float64", "count": 3}},
      {"name": "raw", "type": {"array": "uint8", "count": 24}}
    ]},
    "Team": {"kind": "enum", "underlying": "int32",
             "values": {"TEAM_NONE": -1, "TEAM_RED": 0}},
    "PPlayer": {"kind": "typedef", "type": {"pointer": {"ref": "Player"}}}
  },
  "diagnostics": [],
  "producer": "ida2pdb; IDA 9.2"
}
```

The example validates; its addresses are illustrative.

## Top level

| Field | Required | Content |
| --- | --- | --- |
| `format` | yes | `"ida2pdb"` |
| `image` | yes | image identity |
| `symbols` | yes | array of symbols |
| `types` | no | object mapping type names to definitions |
| `diagnostics` | no | array of collection diagnostics |
| `producer` | no | free-form producer string |

Optional fields holding their default value are omitted on save.

## `image`

| Field | Required | Content |
| --- | --- | --- |
| `arch` | yes | `"x86"` or `"x64"` |
| `image_base` | yes | IDA's image base (informational; all addresses are RVAs) |
| `input_sha256` | no | lowercase hex SHA-256 of IDA's input file; empty if unknown |

`input_sha256` is only used to verify that the executable passed to the build is the analyzed file.  
GUID, age and sections always come from that executable.

## `symbols`

| Field | Required | Content |
| --- | --- | --- |
| `name` | yes | symbol name, verbatim |
| `rva` | yes | unsigned 32-bit RVA |
| `kind` | yes | `"function"` (function start), `"data"` (data item) or `"label"` |
| `size` | no | entry chunk size for functions, IDA item size otherwise |
| `type` | no | [type expression](#type-expressions) |
| `params` | no | parameter names in type order; `""` for unnamed |

Constraints:

- labels have no type; only functions have `params`;
- a function's type must resolve (possibly through typedefs) to a function type;
- `(name, rva)` is unique;
- names are non-empty, NUL-free, and at most 60,000 bytes of UTF-8 (CodeView record size limit).

## Type expressions

A type expression is a builtin name or an object with exactly one discriminating key:

| Form | Meaning |
| --- | --- |
| `"int32"` | builtin |
| `{"ref": "Name"}` | named type from `types` |
| `{"pointer": T}` | pointer of the image's pointer size |
| `{"pointer": T, "size": 4}` | pointer of explicit size, 4 or 8 (`__ptr32`, `__ptr64`) |
| `{"array": T, "count": n}` | array; `0` for an unknown bound |
| `{"function": F}` | function type |
| `{"const": T}`, `{"volatile": T}` | qualified type; nest for both |

Function type `F`:

| Field | Required | Content |
| --- | --- | --- |
| `return` | yes | return type |
| `params` | yes | parameter types |
| `cc` | no | `cdecl` (default), `stdcall`, `pascal`, `fastcall`, `thiscall`, `vectorcall`, `usercall`, `userpurge`, `golang`, `swift`, `unknown` |
| `varargs` | no | `true` for variadic functions |

### Builtins

Builtins name machine types by width rather than C spelling (`short`, `__int16` and `_WORD` are all 16-bit integers).  
Integers of unspecified signedness (`__int32`) are signed; IDA's unknown-type spellings (`_DWORD`) are unsigned.

| Builtin | Bytes | Typical sources |
| --- | --- | --- |
| `void` | 0 | `void`, `_UNKNOWN` |
| `char` | 1 | `char` |
| `wchar`, `char8`, `char16`, `char32` | 2, 1, 2, 4 | `wchar_t`, `char8_t`, `char16_t`, `char32_t` |
| `bool8`, `bool16`, `bool32`, `bool64` | 1, 2, 4, 8 | `bool`, `_BOOL1` … `_BOOL8` |
| `int8` … `int128` | 1 … 16 | `signed char`, `short`, `int`, `__int64`, `__int128` |
| `uint8` … `uint128` | 1 … 16 | `unsigned char`, …, `_BYTE`, `_DWORD`, `_OWORD` |
| `float16`, `float32`, `float64`, `float80`, `float128` | 2, 4, 8, 10, 16 | `float`, `double`, `long double`, `_TBYTE` |

## `types`

Every definition has a `kind`.

### `struct`, `union`

| Field | Required | Content |
| --- | --- | --- |
| `kind` | yes | `"struct"` or `"union"` |
| `size` | no | size in bytes |
| `members` | no | members in IDA order; absent for a declared-only type |
| `anonymous` | no | `true` for anonymous types (IDA's `Outer::$HASH`) |

A declared-only type has neither `members` nor `size`.

Members:

| Field | Content |
| --- | --- |
| `name` | member name; `""` if unnamed |
| `type` | type expression |
| `offset` | byte offset; default `0` |
| `bit_offset`, `bit_width` | bitfields only, instead of `offset`: absolute bit offset from the start of the type, and width |
| `base` | `true` for a base class; `type` must be a `ref` |

- Offsets are IDA's and are not recomputed; members may overlap or leave gaps.
- A bitfield's `type` is the integer builtin of its storage unit, at most 64 bits; `bit_width` may not exceed it.
- An unnamed member of anonymous type is a C anonymous member: its members belong to the enclosing type (`Player.origin` in the example).

### `enum`

| Field | Required | Content |
| --- | --- | --- |
| `kind` | yes | `"enum"` |
| `underlying` | yes | integer builtin, 8 to 64 bits |
| `values` | no | name-to-value mapping in IDA order; absent for a declared-only enum |
| `anonymous` | no | `true` for anonymous enums |

Values must fit the underlying type.

### `typedef`

```json
{"kind": "typedef", "type": {"pointer": "void"}}
```

Typedefs may reference other typedefs, but not cyclically.

### Unresolved references

A `ref` to a name absent from `types` is valid.  
The build emits it as a forward declaration and reports `type_missing`.

## `diagnostics`

| Field | Required | Content |
| --- | --- | --- |
| `code` | yes | diagnostic code (see the README) |
| `message` | yes | human-readable message |
| `symbol` | no | affected symbol or type |

Snapshot diagnostics are carried into the build report and are fatal under `--strict`.
