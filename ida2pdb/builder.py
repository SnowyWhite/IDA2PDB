"""Build a PDB for an executable from a snapshot. IDA is not involved.

    build_pdb(snapshot, exe, output) -> report

The builder checks that the snapshot describes the executable, places every
symbol in the executable's PE sections, lowers the types (codeview.py), and has
the native writer turn the result into a PDB with the executable's GUID and
age. The output is replaced only after the writer succeeded, so a failed or
cancelled build leaves an existing PDB untouched.

Everything that cannot be exported is reported as a diagnostic rather than
silently dropped: a symbol outside every section keeps no public, a typed
symbol whose extent crosses a section keeps only its public, and so on. A
strict build fails on any diagnostic instead.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path, PureWindowsPath
import tempfile

from .codeview import Lowering
from .errors import ExportError
from .model import Diagnostic, Snapshot
from .pe import PEImage
from .toolchain import Toolchain
from .util import write_json


@dataclass
class BuildOptions:
    publics_only: bool = False          # names only: no types, procedures or typed globals
    strict: bool = False                # fail instead of exporting with diagnostics
    allow_image_mismatch: bool = False  # accept an executable whose hash differs from IDA's input


def default_output(exe) -> Path:
    """Where a debugger looks first: the executable's directory, under the PDB
    file name its RSDS record expects."""
    exe = Path(exe)
    return exe.with_name(PureWindowsPath(PEImage.read(exe).pdb_name).name or exe.stem + ".pdb")


def build_pdb(snapshot: Snapshot, exe, output, *, toolchain: Toolchain | None = None,
              options: BuildOptions | None = None) -> dict:
    """Write the PDB and return the report (a JSON-serializable dict).

    All snapshot addresses are RVAs, so a rebased database produces the same
    PDB as the original one.
    """
    snapshot = snapshot.validated()
    options = options or BuildOptions()
    toolchain = toolchain or Toolchain()
    exe = Path(exe).resolve()
    output = Path(output).resolve()
    if output == exe:
        raise ExportError("output PDB must not overwrite the input executable")

    image = PEImage.read(exe)
    if image.arch != snapshot.image.arch:
        raise ExportError(f"architecture mismatch: snapshot {snapshot.image.arch}, PE {image.arch}")
    identity = _identity(snapshot, image, options)

    # Without types, the collector's diagnostics about types concern nothing
    # that is exported.
    diagnostics = [d for d in snapshot.diagnostics
                   if not (options.publics_only and d.code in ("type_unavailable", "member_skipped"))]
    plan = _plan(snapshot, image, options, diagnostics)
    if options.strict and diagnostics:
        raise ExportError("strict export rejected diagnostics:\n" + _summary(diagnostics))

    output.parent.mkdir(parents=True, exist_ok=True)
    writer = toolchain.writer()
    with tempfile.TemporaryDirectory(prefix=".ida2pdb-", dir=output.parent) as directory:
        tmp = Path(directory)
        write_json(tmp / "input.json", {"module": f"{exe.stem} (IDA)",
                                        **plan})
        staged = tmp / "output.pdb"
        result = toolchain.run([writer, exe, tmp / "input.json", staged], timeout=1800)
        try:
            native = json.loads(result.stdout)
        except ValueError as e:
            raise ExportError("the PDB writer returned an invalid report; rebuild ida2pdb-pdbgen") from e
        if not isinstance(native, dict) or not isinstance(native.get("type_records"), int):
            raise ExportError("the PDB writer returned an unexpected report; rebuild ida2pdb-pdbgen")
        if not staged.is_file() or not staged.stat().st_size:
            raise ExportError("the PDB writer succeeded without producing a PDB")
        if toolchain.cancel_event is not None and toolchain.cancel_event.is_set():
            raise ExportError("export cancelled")
        os.replace(staged, output)

    return {
        "output": str(output),
        "image": {"path": str(exe), "arch": image.arch, "sha256": image.sha256, "guid": image.guid,
                  "age": image.age, "pdb_name": image.pdb_name, "identity": identity},
        "input_symbols": len(snapshot.symbols),
        "publics": len(plan["publics"]),
        "functions": len(plan["procedures"]),
        "globals": len(plan["globals"]),
        "typedefs": len(plan["typedefs"]),
        "type_records": native["type_records"],
        "diagnostics": [asdict(d) for d in diagnostics],
    }


def _identity(snapshot, image, options):
    """How sure we are that the snapshot was taken from this executable."""
    expected = snapshot.image.input_sha256
    if not expected:
        return "unverified"
    if expected == image.sha256:
        return "verified"
    if not options.allow_image_mismatch:
        raise ExportError("the snapshot was taken from a different file than the executable "
                          "(SHA-256 differs); use --allow-image-mismatch only for an address-compatible "
                          "build of the same image, such as a patched copy")
    return "mismatch"


def _plan(snapshot, image, options, diagnostics) -> dict:
    """The writer's input (less the module name): the symbols placed in the
    executable's sections and the types lowered. What does not fit is added to
    diagnostics."""
    lowering = None if options.publics_only else Lowering(snapshot)
    publics, procedures, globals_ = [], [], []

    for symbol in snapshot.symbols:
        section = image.section_at(symbol.rva)
        if section is None:
            diagnostics.append(Diagnostic("outside_sections",
                                          f"RVA {symbol.rva:#x} lies in no PE section, so no PDB symbol can "
                                          "name it", symbol.name))
            continue
        publics.append({"name": symbol.name, "rva": symbol.rva, "function": symbol.kind == "function"})
        if lowering is None or symbol.type is None:
            continue

        if symbol.kind == "function":
            if not lowering.is_function(symbol.type):
                diagnostics.append(Diagnostic("invalid_function_type", "The function's type is not a function "
                                              "type; it keeps only its public", symbol.name))
                continue
            # A public stays useful when IDA's extent crosses a section, but
            # claiming that extent for a procedure would be wrong.
            if not section.contains(symbol.rva, symbol.size):
                diagnostics.append(Diagnostic("invalid_extent", "The function extends past its PE section; it "
                                              "keeps only its public", symbol.name))
                continue
            # The parameters get IDA's names where the snapshot has them, so
            # that a debugger can show the signature.
            param_types = lowering.resolve(symbol.type)["function"]["params"]
            names = symbol.params
            if names and len(names) != len(param_types):
                diagnostics.append(Diagnostic("invalid_parameters", f"{len(names)} parameter names for "
                                              f"{len(param_types)} parameters; the names are left out",
                                              symbol.name))
                names = []
            params = [{"name": names[i] if names else "", "type": lowering.index(t)}
                      for i, t in enumerate(param_types)]
            procedures.append({"name": symbol.name, "rva": symbol.rva, "size": symbol.size,
                               "type": lowering.index(symbol.type), "params": params})
        else:
            if not section.contains(symbol.rva, lowering.size(symbol.type)):
                diagnostics.append(Diagnostic("invalid_extent", "The global's type extends past its PE section; it "
                                              "keeps only its public", symbol.name))
                continue
            globals_.append({"name": symbol.name, "rva": symbol.rva, "type": lowering.index(symbol.type)})

    typedefs, types = [], []
    if lowering is not None:
        lowering.define_all()
        typedefs = lowering.typedefs()
        lowering.finish()
        types = lowering.records
        diagnostics.extend(lowering.diagnostics)

    return {"types": types, "procedures": procedures, "globals": globals_, "typedefs": typedefs,
            "publics": publics}


def _summary(diagnostics, limit=20):
    """The diagnostic codes with their counts, then up to limit diagnostics."""
    counts = Counter(d.code for d in diagnostics)
    lines = [", ".join(f"{code} x{n}" for code, n in counts.most_common())]
    if limit:
        lines += [f"  {d.code} {d.symbol}: {d.message}".rstrip() for d in diagnostics[:limit]]
        if len(diagnostics) > limit:
            lines.append(f"  ... and {len(diagnostics) - limit} more")
    return "\n".join(lines)


def summarize(report: dict) -> str:
    """A few human-readable lines about a build_pdb report."""
    image = report["image"]
    identity = {"verified": "matches the snapshot's input file",
                "unverified": "not verified: the snapshot records no input hash",
                "mismatch": "differs from the snapshot's input file (allowed)"}[image["identity"]]
    lines = [report["output"],
             f"  {report['publics']} publics, {report['functions']} typed functions, {report['globals']} typed "
             f"globals, {report['typedefs']} typedefs, {report['type_records']} type records",
             f"  GUID {{{image['guid'].upper()}}} age {image['age']} of {Path(image['path']).name}; {identity}"]
    expected = PureWindowsPath(image["pdb_name"]).name
    if expected and expected.lower() != Path(report["output"]).name.lower():
        lines.append(f"  note: the executable asks for {expected}; debuggers search for that file name")
    diagnostics = [Diagnostic(**d) for d in report["diagnostics"]]
    if diagnostics:
        lines.append(f"  {len(diagnostics)} diagnostics: " + _summary(diagnostics, limit=0))
    return "\n".join(lines)
