"""IDA plugin: Edit > Plugins > Export PDB.

Collects the open database on IDA's main thread, then builds the PDB in a
worker thread so that IDA stays responsive; running the plugin again while a
build is in progress cancels it. The plugin can also save the snapshot alone,
to build the PDB later (or elsewhere) with `ida2pdb build`.

Install the folder containing this file, with the ida2pdb package beside it,
into IDA's user plugins directory (README.md).
"""
from pathlib import Path
import queue
import sys
import threading
import weakref

import ida_idaapi
import ida_kernwin
import ida_loader
import ida_nalt

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ida2pdb.builder import build_pdb, default_output, summarize  # noqa: E402
from ida2pdb.errors import ExportError  # noqa: E402
from ida2pdb.ida_collect import CollectOptions, collect_current  # noqa: E402
from ida2pdb.toolchain import Toolchain  # noqa: E402
from ida2pdb.util import distinct_paths, write_json  # noqa: E402

PREFIX = "IDA2PDB"
POLL_MS = 200


def _build(snapshot, exe, output, results, cancel):
    """The worker thread. It owns no IDA object: all UI work stays in the timer."""
    try:
        report = build_pdb(snapshot, exe, output, toolchain=Toolchain(cancel_event=cancel))
        write_json(str(output) + ".report.json", report)
        results.put((report, None))
    except Exception as error:  # reported in IDA; nothing may escape the thread
        results.put((None, str(error)))


class ExportModule(ida_idaapi.plugmod_t):
    def __init__(self):
        super().__init__()
        self.cancel = threading.Event()
        self.results = queue.Queue()
        self.timer = None

    def run(self, arg):
        if self.timer is not None:
            self.cancel.set()
            ida_kernwin.msg(f"{PREFIX}: cancelling the running build.\n")
            return

        mode = ida_kernwin.ask_buttons("PDB", "Snapshot", "Cancel", 1,
                                       "Export names and types of this database as a PDB for its executable, "
                                       "or as a JSON snapshot to build the PDB later?")
        if mode not in (0, 1):
            return
        pdb = mode == 1
        types = ida_kernwin.ask_yn(1, "Include the types you assigned?\nChoose No to export names only.")
        if types == -1:
            return
        options = CollectOptions(types="referenced" if types == 1 else "none")

        input_path = ida_nalt.get_input_file_path()
        exe = None
        if pdb:
            exe = ida_kernwin.ask_file(False, input_path, "The executable the PDB is for")
            if not exe:
                return
        try:
            default = default_output(exe) if pdb else Path(input_path or "export").with_suffix(".symbols.json")
        except ExportError as error:
            ida_kernwin.warning(f"{PREFIX}: {error}")
            return
        output = ida_kernwin.ask_file(True, str(default), "Save PDB" if pdb else "Save snapshot")
        if not output:
            return

        try:
            distinct_paths([input_path or None, exe, ida_loader.get_path(ida_loader.PATH_TYPE_IDB)],
                           [output, str(output) + ".report.json" if pdb else None])
            ida_kernwin.show_wait_box("Collecting names and types...")
            try:
                snapshot = collect_current(options, cancelled=ida_kernwin.user_cancelled)
            finally:
                ida_kernwin.hide_wait_box()
            if not pdb:
                snapshot.save(output)
                ida_kernwin.msg(f"{PREFIX}: saved {len(snapshot.symbols)} symbols and {len(snapshot.types)} types "
                                f"to {output}\n")
                return
            self._start(snapshot, exe, output)
        except Exception as error:
            self._stop()
            ida_kernwin.warning(f"{PREFIX}: {error}")

    def _start(self, snapshot, exe, output):
        self.cancel = threading.Event()
        self.results = queue.Queue()
        # The timer must not keep the module alive after IDA closes the
        # database, or __del__ could never cancel the build.
        module = weakref.ref(self)
        self.timer = ida_kernwin.register_timer(POLL_MS, lambda: module()._poll() if module() else -1)
        if self.timer is None:
            raise ExportError("cannot register the progress timer")
        threading.Thread(target=_build, args=(snapshot, exe, output, self.results, self.cancel),
                         daemon=True).start()
        ida_kernwin.msg(f"{PREFIX}: building {output} in the background; run the plugin again to cancel.\n")

    def _stop(self):
        self.cancel.set()
        if self.timer is not None:
            ida_kernwin.unregister_timer(self.timer)
            self.timer = None

    def _poll(self):
        try:
            report, error = self.results.get_nowait()
        except queue.Empty:
            return POLL_MS
        self.timer = None  # returning -1 unregisters it
        if error:
            ida_kernwin.warning(f"{PREFIX}: {error}")
        else:
            ida_kernwin.msg(f"{PREFIX}: {summarize(report)}\n")
            for d in report["diagnostics"]:
                ida_kernwin.msg(f"  {d['code']} {d['symbol']}: {d['message']}\n")
        return -1

    def __del__(self):
        self._stop()


class ExportPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    comment = "Export names and types to a PDB that matches the executable"
    help = "Run again while a build is in progress to cancel it."
    wanted_name = "Export PDB"
    wanted_hotkey = ""

    def init(self):
        return ExportModule()


def PLUGIN_ENTRY():
    return ExportPlugin()
