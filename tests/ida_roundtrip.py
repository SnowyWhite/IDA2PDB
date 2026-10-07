"""Driver for test_ida, run in its own idalib process: python ida_roundtrip.py <config.json>.

It creates a database for the fixture executable, declares the fixture's types
in IDA, names and types the fixture's symbols, and collects the database
before and after rebasing it. The collected snapshot and the packed database go
where the config says. It only ever touches the fixture.
"""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

import idapro  # noqa: E402

# Initializing IDAPython may replace the import path.
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

import ida_auto  # noqa: E402
import ida_loader  # noqa: E402
import ida_name  # noqa: E402
import ida_nalt  # noqa: E402
import ida_segment  # noqa: E402
import ida_typeinf  # noqa: E402

from ida2pdb.ida_collect import CollectOptions, collect_current  # noqa: E402
from fixtures import FIXTURE_DECLARATIONS  # noqa: E402

SYMBOLS = {
    "sample": "int __cdecl renamed_sample(int value);",
    "variadic": "int __cdecl renamed_variadic(const char *format, ...);",
    "record": "RecordAlias renamed_record;",
    "values": "int renamed_values[3];",
    "node": "struct Node renamed_node;",
    "packed": "struct Packed renamed_packed;",
}


def main():
    config = json.loads(Path(sys.argv[1]).read_text())
    assert idapro.open_database(config["exe"], True) == 0
    try:
        import ida2pdb_plugin

        # The plugin loads and initializes; its dialogs need the GUI.
        assert ida2pdb_plugin.PLUGIN_ENTRY().init() is not None

        assert ida_typeinf.parse_decls(None, FIXTURE_DECLARATIONS, None, 0) == 0
        base = ida_nalt.get_imagebase()
        for name, declaration in SYMBOLS.items():
            ea = base + config["addresses"][name]
            assert ida_name.set_name(ea, "renamed_" + name, ida_name.SN_CHECK), name
            tif = ida_typeinf.tinfo_t()
            assert ida_typeinf.parse_decl(tif, None, declaration, ida_typeinf.PT_SIL), name
            assert ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE), name
        ida_auto.auto_wait()

        options = CollectOptions(include="^renamed_")
        before = collect_current(options)
        assert len(before.symbols) == len(SYMBOLS)
        assert all(s.type is not None for s in before.symbols)
        assert ida_segment.rebase_program(0x100000, ida_segment.MSF_FIXONCE) == 0
        after = collect_current(options)
        assert after.image.image_base == before.image.image_base + 0x100000
        assert after.symbols == before.symbols and after.types == before.types
        after.save(config["snapshot"])
        assert ida_loader.save_database(config["database"], ida_loader.DBFL_COMP)
    finally:
        idapro.close_database(save=False)


if __name__ == "__main__":
    main()
