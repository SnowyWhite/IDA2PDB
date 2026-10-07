"""Export IDA names and types to a PDB that matches the executable.

    model        the snapshot: what a PDB is built from (docs/snapshot-format.md)
    ida_collect  takes a snapshot of an IDA database; the only module using IDA
    codeview     lowers the snapshot's types to CodeView records
    builder      checks the executable, places the symbols, runs the writer
    pe           reads the executable's sections and RSDS identity
    toolchain    finds or builds the native writer (native/pdbgen.cxx)
    cli          the ida2pdb command

Building a PDB from a snapshot needs neither IDA nor a decompiler license.
"""
