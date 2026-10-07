"""The ida2pdb command line.

    ida2pdb export  <database> --exe <exe> [-o <pdb>]   collect and build in one step
    ida2pdb collect <database> -o <snapshot.json>       collect only (needs idalib)
    ida2pdb build   <snapshot> --exe <exe> [-o <pdb>]   build only (needs no IDA)
    ida2pdb build-writer [-o <path>] [--static]         compile the native writer

README.md describes the options in context.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .builder import BuildOptions, build_pdb, default_output, summarize
from .errors import ExportError
from .ida_collect import CollectOptions, collect_database
from .model import Snapshot
from .toolchain import Toolchain
from .util import distinct_paths, write_json


def _collect_arguments(parser):
    parser.add_argument("database", type=Path, help="closed, packed IDA database (.i64 or .idb)")
    group = parser.add_argument_group("what to collect")
    group.add_argument("--names", choices=("user", "all"), default="user",
                       help="user-assigned names only (default), or IDA's whole name list")
    group.add_argument("--types", choices=("none", "referenced", "all"), default="referenced",
                       help="no types, the types the symbols use (default), or all local types as well")
    group.add_argument("--inferred-types", action="store_true",
                       help="also use symbol types IDA guessed, not only those set explicitly")
    group.add_argument("--include", default="", metavar="REGEX", help="only names matching this expression")
    group.add_argument("--exclude", default="", metavar="REGEX", help="leave out names matching this expression")
    group.add_argument("--segment", action="append", default=[], metavar="NAME",
                       help="only names in this IDA segment (repeatable)")


def _tool_arguments(parser):
    group = parser.add_argument_group("native writer")
    group.add_argument("--pdbgen", metavar="EXE", help="prebuilt ida2pdb-pdbgen (default: $IDA2PDB_PDBGEN, PATH, "
                                                       "or a cached build)")
    group.add_argument("--llvm-config", metavar="EXE", help="llvm-config of the LLVM to build the writer against "
                                                            "(default: $LLVM_CONFIG or llvm-config)")
    group.add_argument("--cxx", metavar="EXE", help="C++ compiler for the writer (default: $IDA2PDB_CXX or the "
                                                    "clang++ beside llvm-config)")
    group.add_argument("--cache-dir", type=Path, metavar="DIR", help="cache for writer builds")


def _build_arguments(parser):
    parser.add_argument("--exe", required=True, type=Path, help="the executable the PDB is for (needs an RSDS "
                                                                 "debug record)")
    parser.add_argument("-o", "--output", type=Path, help="PDB to write (default: the file name the executable "
                                                          "expects, next to it)")
    parser.add_argument("--report", type=Path, metavar="FILE", help="also write the full report as JSON")
    parser.add_argument("--json", action="store_true", help="print the full report as JSON instead of a summary")
    parser.add_argument("--publics-only", action="store_true", help="export names only: no types, procedures "
                                                                     "or typed globals")
    parser.add_argument("--strict", action="store_true", help="fail, leaving any existing PDB alone, instead of "
                                                              "exporting with diagnostics")
    parser.add_argument("--allow-image-mismatch", action="store_true",
                        help="accept an executable whose SHA-256 differs from IDA's input file (a patched copy "
                             "with the same layout)")
    _tool_arguments(parser)


def parser():
    ap = argparse.ArgumentParser(prog="ida2pdb", description="Export IDA names and types to a PDB that matches "
                                                            "the executable, for WinDbg, x64dbg and other "
                                                            "debuggers.")
    sub = ap.add_subparsers(dest="command", required=True, metavar="command")

    export = sub.add_parser("export", help="collect a database and build its PDB")
    _collect_arguments(export)
    _build_arguments(export)
    export.add_argument("--snapshot", type=Path, metavar="FILE", help="also save the collected snapshot")

    collect = sub.add_parser("collect", help="collect a portable JSON snapshot through idalib")
    _collect_arguments(collect)
    collect.add_argument("-o", "--output", required=True, type=Path, help="snapshot to write")

    build = sub.add_parser("build", help="build a PDB from a snapshot; IDA is not needed")
    build.add_argument("snapshot", type=Path)
    _build_arguments(build)

    writer = sub.add_parser("build-writer", help="compile the native writer against a local LLVM")
    writer.add_argument("-o", "--output", type=Path, help="where to put it (default: the cache)")
    writer.add_argument("--static", action="store_true", help="link LLVM statically, for a self-contained "
                                                              "executable")
    _tool_arguments(writer)
    return ap


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        tools = Toolchain(pdbgen=args.pdbgen, llvm_config=args.llvm_config, cxx=args.cxx,
                          cache_dir=args.cache_dir) if args.command != "collect" else None
        if args.command == "build-writer":
            print(tools.build_writer(args.output, static=args.static))
            return 0

        if args.command in ("build", "export") and args.output is None:
            args.output = default_output(args.exe)
        if args.command == "collect":
            distinct_paths([args.database], [args.output])
        elif args.command == "build":
            distinct_paths([args.exe, args.snapshot], [args.output, args.report])
        else:
            distinct_paths([args.exe, args.database], [args.output, args.report, args.snapshot])

        if args.command == "build":
            snapshot = Snapshot.load(args.snapshot)
        else:
            options = CollectOptions(args.names, args.types, args.inferred_types, args.include, args.exclude,
                                     args.segment)
            snapshot = collect_database(args.database, options)
            if args.command == "collect":
                snapshot.save(args.output)
                print(f"{args.output}: {len(snapshot.symbols)} symbols, {len(snapshot.types)} types, "
                      f"{len(snapshot.diagnostics)} diagnostics")
                return 0
            if args.snapshot:
                snapshot.save(args.snapshot)

        options = BuildOptions(args.publics_only, args.strict, args.allow_image_mismatch)
        report = build_pdb(snapshot, args.exe, args.output, toolchain=tools, options=options)
        if args.report:
            write_json(args.report, report)
        print(json.dumps(report, ensure_ascii=False, indent=2) if args.json else summarize(report))
        return 0
    except (ExportError, OSError) as e:
        print(f"ida2pdb: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("ida2pdb: cancelled", file=sys.stderr)
        return 130
