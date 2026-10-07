"""Build the IDA plugin archive: python tools/package_plugin.py dist/ida2pdb.zip

The archive holds one folder, ida2pdb/, to extract into IDA's user
plugins directory: the plugin entry point and its metadata, the ida2pdb package
(with the writer's source) and the documentation. With --writer, a prebuilt
ida2pdb-pdbgen goes in as ida2pdb/bin/, so the plugin needs no LLVM.
"""
import argparse
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FOLDER = "ida2pdb"


def files():
    out = [ROOT / name for name in ("ida-plugin.json", "ida2pdb_plugin.py", "README.md", "LICENSE")]
    out += (ROOT / "docs").glob("*.md")
    out += (ROOT / "docs" / "images").glob("*.png")
    out += [p for p in (ROOT / "ida2pdb").rglob("*") if p.suffix in (".py", ".cxx") and "__pycache__" not in p.parts]
    return sorted(p for p in out if p.is_file())


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("output", type=Path, help="the .zip to write")
    parser.add_argument("--writer", type=Path, help="a prebuilt (static) ida2pdb-pdbgen to include")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in files():
            archive.write(path, f"{FOLDER}/{path.relative_to(ROOT).as_posix()}")
        if args.writer:
            archive.write(args.writer, f"{FOLDER}/ida2pdb/bin/ida2pdb-pdbgen{args.writer.suffix}")
    print(args.output)


if __name__ == "__main__":
    main()
