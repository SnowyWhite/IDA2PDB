"""The small part of the PE format the builder needs.

A PDB matches an executable by the GUID and age in the executable's RSDS
CodeView debug record, and places symbols by section and offset. That is all
read here: the machine, the image base, the section table and the RSDS record.
Everything is bounds-checked; a truncated or inconsistent file is an error.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct
import uuid

from .errors import ExportError

MACHINES = {0x014c: "x86", 0x8664: "x64"}
OPTIONAL_MAGIC = {"x86": 0x10b, "x64": 0x20b}

IMAGE_DEBUG_TYPE_CODEVIEW = 2
DEBUG_DIRECTORY_INDEX = 6
DEBUG_DIRECTORY_ENTRY_SIZE = 28
SECTION_HEADER_SIZE = 40


@dataclass(frozen=True)
class Section:
    name: str
    rva: int
    virtual_size: int
    raw_size: int
    raw_offset: int
    characteristics: int

    @property
    def end(self):
        # The larger of the two sizes, as the native writer measures it too: a
        # section's raw data may be longer than its virtual size (alignment
        # padding), and IDA may name an address in that padding.
        return self.rva + max(self.virtual_size, self.raw_size)

    def contains(self, rva, size=0):
        """Whether [rva, rva + size) lies within this section."""
        return self.rva <= rva < self.end and rva + size <= self.end


@dataclass(frozen=True)
class PEImage:
    arch: str
    image_base: int
    sha256: str
    sections: tuple[Section, ...]
    guid: str
    age: int
    pdb_name: str

    def section_at(self, rva, size=0):
        """The section holding [rva, rva + size), or None."""
        return next((s for s in self.sections if s.contains(rva, size)), None)

    @classmethod
    def read(cls, path):
        try:
            data = Path(path).read_bytes()
        except OSError as e:
            raise ExportError(f"cannot read PE {path}: {e}") from e

        def need(offset, size):
            if offset < 0 or size < 0 or offset + size > len(data):
                raise ExportError(f"{path}: truncated PE structure at file offset {offset:#x}")

        def unpack(fmt, offset):
            need(offset, struct.calcsize(fmt))
            return struct.unpack_from(fmt, data, offset)

        # DOS header, PE signature, COFF file header.
        if data[:2] != b"MZ":
            raise ExportError(f"{path}: expected a Windows PE executable")
        pe, = unpack("<I", 0x3c)
        need(pe, 24)
        if data[pe:pe + 4] != b"PE\0\0":
            raise ExportError(f"{path}: invalid PE signature")
        machine, section_count, _, _, _, optional_size, _ = unpack("<HHIIIHH", pe + 4)
        arch = MACHINES.get(machine)
        if arch is None:
            raise ExportError(f"{path}: unsupported PE machine {machine:#x}; expected x86 or x64")

        # Optional header: image base and the debug data directory.
        optional = pe + 24
        need(optional, optional_size)
        magic, = unpack("<H", optional)
        if magic != OPTIONAL_MAGIC[arch]:
            raise ExportError(f"{path}: PE optional header disagrees with machine")
        directories = 112 if arch == "x64" else 96
        if optional_size < directories + (DEBUG_DIRECTORY_INDEX + 1) * 8:
            raise ExportError(f"{path}: PE has no debug data directory")
        image_base, = unpack("<Q" if arch == "x64" else "<I", optional + (24 if arch == "x64" else 28))
        directory_count, = unpack("<I", optional + directories - 4)
        debug_rva, debug_size = unpack("<II", optional + directories + DEBUG_DIRECTORY_INDEX * 8)
        if directory_count <= DEBUG_DIRECTORY_INDEX or not debug_rva or not debug_size \
                or debug_size % DEBUG_DIRECTORY_ENTRY_SIZE:
            raise ExportError(f"{path}: PE has no valid debug data directory / RSDS record")

        # Section table.
        if not section_count:
            raise ExportError(f"{path}: PE has no sections")
        sections = []
        for i in range(section_count):
            fields = unpack("<8sIIIIIIHHI", optional + optional_size + i * SECTION_HEADER_SIZE)
            name, virtual_size, rva, raw_size, raw_offset = fields[:5]
            if rva + max(virtual_size, raw_size) > (1 << 32):
                raise ExportError(f"{path}: PE section range overflows RVA space")
            if raw_size:
                need(raw_offset, raw_size)
            section = Section(name.rstrip(b"\0").decode("ascii", "replace"), rva, virtual_size,
                              raw_size, raw_offset, fields[-1])
            if any(section.contains(other.rva) or other.contains(section.rva) for other in sections):
                raise ExportError(f"{path}: overlapping PE sections")
            sections.append(section)

        def file_offset(rva, size):
            for s in sections:
                if s.rva <= rva and rva - s.rva + size <= s.raw_size:
                    return s.raw_offset + rva - s.rva
            raise ExportError(f"{path}: debug directory points outside file-backed sections")

        # Debug directory: the RSDS record(s). Linkers may write the record more
        # than once; all copies must agree.
        identities = []
        debug = file_offset(debug_rva, debug_size)
        for entry in range(debug, debug + debug_size, DEBUG_DIRECTORY_ENTRY_SIZE):
            _, _, _, _, kind, size, _, raw = unpack("<IIHHIIII", entry)
            if kind != IMAGE_DEBUG_TYPE_CODEVIEW:
                continue
            need(raw, size)
            if size < 24 or data[raw:raw + 4] != b"RSDS":
                continue
            guid = str(uuid.UUID(bytes_le=data[raw + 4:raw + 20]))
            age, = unpack("<I", raw + 20)
            name = data[raw + 24:raw + size].split(b"\0", 1)[0].decode("utf-8", "replace")
            identities.append((guid, age, name))
        if not identities:
            raise ExportError(f"{path}: no RSDS CodeView record; a matching PDB identity is required")
        if len({(guid, age) for guid, age, _ in identities}) != 1:
            raise ExportError(f"{path}: conflicting RSDS CodeView records")

        return cls(arch, image_base, hashlib.sha256(data).hexdigest(), tuple(sections), *identities[0])
