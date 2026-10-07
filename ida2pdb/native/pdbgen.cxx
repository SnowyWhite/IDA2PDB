// ida2pdb-pdbgen: write a PDB for a PE image from records prepared by ida2pdb.
//
//   ida2pdb-pdbgen <exe> <input.json> <out.pdb>
//
// All decisions about what to describe are made on the Python side
// (codeview.py, builder.py); this program only turns them into PDB streams:
//
//   - the input's type records become the TPI stream, with the hashes a
//     debugger uses to find a type by name and to resolve the forward
//     references the records use for every named structure;
//   - each procedure becomes an S_GPROC32, with an S_LOCAL per parameter, in a
//     single module, referenced from the globals stream by an S_PROCREF and
//     covered by a section contribution;
//   - each typed global becomes an S_GDATA32 and each typedef an S_UDT in the
//     globals stream;
//   - each public becomes an S_PUB32;
//   - the executable's section headers go in as they are, because debuggers map
//     a symbol's section:offset to an address through them.
//
// The PDB carries the executable's own GUID and age (from its RSDS record), so
// a debugger accepts it for that executable without being told to. The input
// is validated completely: a malformed file is an error, never a crash or a
// partially written PDB.
//
// The result is one line of JSON on stdout: {"type_records": <count>}.

#include <llvm/ADT/APSInt.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/DebugInfo/CodeView/AppendingTypeTableBuilder.h>
#include <llvm/DebugInfo/CodeView/ContinuationRecordBuilder.h>
#include <llvm/DebugInfo/CodeView/SymbolRecord.h>
#include <llvm/DebugInfo/CodeView/SymbolSerializer.h>
#include <llvm/DebugInfo/CodeView/TypeRecord.h>
#include <llvm/DebugInfo/MSF/MSFBuilder.h>
#include <llvm/DebugInfo/PDB/Native/DbiModuleDescriptorBuilder.h>
#include <llvm/DebugInfo/PDB/Native/DbiStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/GSIStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/InfoStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/PDBFileBuilder.h>
#include <llvm/DebugInfo/PDB/Native/RawConstants.h>
#include <llvm/DebugInfo/PDB/Native/RawTypes.h>
#include <llvm/DebugInfo/PDB/Native/TpiHashing.h>
#include <llvm/DebugInfo/PDB/Native/TpiStreamBuilder.h>
#include <llvm/Object/COFF.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/Parallel.h>
#include <llvm/Support/raw_ostream.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <optional>
#include <utility>
#include <vector>

using namespace llvm;
using namespace llvm::codeview;
using namespace llvm::object;
using namespace llvm::pdb;

namespace
{
  ExitOnError check ("ida2pdb-pdbgen: ");

  [[noreturn]] void
  fail (const Twine& message)
  {
    check (createStringError (inconvertibleErrorCode (), message));
    std::abort (); // check() exits; this only tells the compiler so.
  }

  // A section-relative address, the form every CodeView record uses.
  //
  struct address
  {
    uint16_t segment;
    uint32_t offset;
  };

  // The executable: its identity and its sections.
  //
  struct image
  {
    std::unique_ptr<MemoryBuffer> buffer;
    std::unique_ptr<COFFObjectFile> coff;
    std::vector<coff_section> sections;
    codeview::GUID guid;
    uint32_t age;
    uint32_t signature;
    COFF::MachineTypes machine;

    // The bytes a section spans in memory. pe.py uses the same extent, so
    // that what the builder accepted is accepted here too.
    //
    static uint64_t
    extent (const coff_section& s)
    {
      return std::max<uint32_t> (s.VirtualSize, s.SizeOfRawData);
    }

    // The section holding [rva, rva + size). A name in the PE header
    // (__ImageBase) lies in no section and has no section-relative address
    // to give; the builder has already left such names out.
    //
    address
    at (uint32_t rva, uint32_t size, StringRef name) const
    {
      for (size_t i (0); i != sections.size (); ++i)
      {
        const coff_section& s (sections[i]);
        uint64_t end (uint64_t (s.VirtualAddress) + extent (s));

        if (rva >= s.VirtualAddress && rva < end && rva + uint64_t (size) <= end)
          return address {static_cast<uint16_t> (i + 1), rva - s.VirtualAddress};
      }

      fail (name + " at rva 0x" + utohexstr (rva) + " lies outside the PE sections");
    }
  };

  image
  read_image (StringRef path)
  {
    image r;
    r.buffer = check (errorOrToExpected (MemoryBuffer::getFile (path)));
    r.coff   = check (COFFObjectFile::create (r.buffer->getMemBufferRef ()));

    for (const SectionRef& s: r.coff->sections ())
      r.sections.push_back (*r.coff->getCOFFSection (s));

    if (r.sections.empty () || r.sections.size () > std::numeric_limits<uint16_t>::max ())
      fail ("invalid PE section count");

    const codeview::DebugInfo* info (nullptr);
    StringRef pdb;
    check (r.coff->getDebugPDBInfo (info, pdb));

    if (info == nullptr || info->Signature.CVSignature != OMF::Signature::PDB70)
      fail (path + " has no RSDS CodeView record");

    std::memcpy (r.guid.Guid, info->PDB70.Signature, sizeof (r.guid.Guid));
    r.age = info->PDB70.Age;
    r.signature = r.coff->getTimeDateStamp ();
    r.machine = static_cast<COFF::MachineTypes> (r.coff->getMachine ());

    if (r.machine != COFF::IMAGE_FILE_MACHINE_I386 &&
        r.machine != COFF::IMAGE_FILE_MACHINE_AMD64)
      fail ("only x86 and x64 PE images are supported");

    return r;
  }

  // Strict accessors for the input. Every field is required.
  //
  const json::Object&
  as_object (const json::Value& v, StringRef what)
  {
    const json::Object* o (v.getAsObject ());
    if (o == nullptr)
      fail (what + " must be an object");
    return *o;
  }

  const json::Value&
  field (const json::Object& o, StringRef key)
  {
    const json::Value* v (o.get (key));
    if (v == nullptr)
      fail ("missing field " + key);
    return *v;
  }

  StringRef
  text (const json::Object& o, StringRef key, bool nonempty = true)
  {
    std::optional<StringRef> v (field (o, key).getAsString ());
    if (!v || (nonempty && v->empty ()) || v->size () > 60000 || v->contains ('\0'))
      fail (key + " must be text without NUL, at most 60000 bytes" +
            (nonempty ? " and not empty" : ""));
    return *v;
  }

  uint64_t
  unsigned_integer (const json::Value& value, StringRef what, uint64_t max)
  {
    std::optional<uint64_t> v (value.getAsUINT64 ());
    if (!v || *v > max)
      fail (what + " must be an unsigned integer up to " + Twine (max));
    return *v;
  }

  uint64_t
  unsigned_integer (const json::Object& o, StringRef key, uint64_t max)
  {
    return unsigned_integer (field (o, key), key, max);
  }

  uint32_t
  uint32 (const json::Object& o, StringRef key)
  {
    return static_cast<uint32_t> (
      unsigned_integer (o, key, std::numeric_limits<uint32_t>::max ()));
  }

  bool
  boolean (const json::Object& o, StringRef key)
  {
    std::optional<bool> v (field (o, key).getAsBoolean ());
    if (!v)
      fail (key + " must be a boolean");
    return *v;
  }

  const json::Array&
  array (const json::Object& o, StringRef key)
  {
    const json::Array* a (field (o, key).getAsArray ());
    if (a == nullptr)
      fail (key + " must be an array");
    return *a;
  }

  // The type records, appended in input order. A type reference in the input
  // below 0x1000 is a simple type, which needs no record. Any other is 0x1000
  // plus the position of an earlier input record. That is not necessarily the
  // record's final index: a long field list is split into several records,
  // each with an index of its own, so positions are mapped here.
  //
  class type_table
  {
  public:
    explicit
    type_table (BumpPtrAllocator& a)
        : table_ (a)
    {
    }

    TypeIndex
    reference (const json::Value& value, StringRef what) const
    {
      uint32_t v (static_cast<uint32_t> (
        unsigned_integer (value, what, std::numeric_limits<uint32_t>::max ())));

      if (v < TypeIndex::FirstNonSimpleIndex)
        return TypeIndex (v);

      uint32_t position (v - TypeIndex::FirstNonSimpleIndex);
      if (position >= indexes_.size ())
        fail (what + " refers to a type record that does not precede it");

      return indexes_[position];
    }

    TypeIndex
    reference (const json::Object& o, StringRef key) const
    {
      return reference (field (o, key), key);
    }

    // Whether ti is a record (not a simple type) of the given kind.
    //
    bool
    is (TypeIndex ti, TypeLeafKind kind)
    {
      return !ti.isSimple () && !ti.isNoneType () && table_.getType (ti).kind () == kind;
    }

    void
    add (const json::Object& o)
    {
      StringRef leaf (text (o, "leaf"));
      TypeIndex r;

      if (leaf == "modifier")
      {
        ModifierOptions m (ModifierOptions::None);
        if (boolean (o, "const"))
          m |= ModifierOptions::Const;
        if (boolean (o, "volatile"))
          m |= ModifierOptions::Volatile;

        ModifierRecord t (reference (o, "type"), m);
        r = table_.writeLeafType (t);
      }
      else if (leaf == "pointer")
      {
        uint64_t size (unsigned_integer (o, "size", 8));
        if (size != 4 && size != 8)
          fail ("pointer size must be 4 or 8");

        PointerOptions p (PointerOptions::None);
        if (boolean (o, "const"))
          p |= PointerOptions::Const;
        if (boolean (o, "volatile"))
          p |= PointerOptions::Volatile;

        PointerRecord t (reference (o, "referent"),
                         size == 8 ? PointerKind::Near64 : PointerKind::Near32,
                         PointerMode::Pointer,
                         p,
                         static_cast<uint8_t> (size));
        r = table_.writeLeafType (t);
      }
      else if (leaf == "array")
      {
        ArrayRecord t (reference (o, "element"),
                       reference (o, "index"),
                       unsigned_integer (o, "size", std::numeric_limits<uint64_t>::max ()),
                       "");
        r = table_.writeLeafType (t);
      }
      else if (leaf == "arglist")
      {
        std::vector<TypeIndex> args;
        for (const json::Value& a: array (o, "args"))
          args.push_back (reference (a, "argument"));

        ArgListRecord t (TypeRecordKind::ArgList, args);
        r = table_.writeLeafType (t);
      }
      else if (leaf == "procedure")
      {
        ProcedureRecord t (reference (o, "return"),
                           static_cast<CallingConvention> (unsigned_integer (o, "cc", 0xff)),
                           FunctionOptions::None,
                           static_cast<uint16_t> (unsigned_integer (o, "count", 0xffff)),
                           reference (o, "args"));

        if (!is (t.ArgumentList, LF_ARGLIST))
          fail ("procedure args must refer to an argument list");

        r = table_.writeLeafType (t);
      }
      else if (leaf == "bitfield")
      {
        BitFieldRecord t (reference (o, "type"),
                          static_cast<uint8_t> (unsigned_integer (o, "width", 64)),
                          static_cast<uint8_t> (unsigned_integer (o, "position", 63)));
        r = table_.writeLeafType (t);
      }
      else if (leaf == "fieldlist")
      {
        ContinuationRecordBuilder b;
        b.begin (ContinuationRecordKind::FieldList);

        for (const json::Value& v: array (o, "fields"))
        {
          const json::Object& f (as_object (v, "field"));
          StringRef kind (text (f, "kind"));

          if (kind == "member")
          {
            DataMemberRecord m (MemberAccess::Public,
                                reference (f, "type"),
                                uint32 (f, "offset"),
                                text (f, "name", false));
            b.writeMemberType (m);
          }
          else if (kind == "base")
          {
            BaseClassRecord m (MemberAccess::Public,
                               reference (f, "type"),
                               uint32 (f, "offset"));
            b.writeMemberType (m);
          }
          else if (kind == "enumerator")
          {
            // CodeView encodes a value in the smallest numeric leaf that
            // holds it, signed only when it is negative.
            //
            const json::Value& value (field (f, "value"));
            APSInt n;

            if (std::optional<uint64_t> u = value.getAsUINT64 ())
              n = APSInt (APInt (64, *u), true /* unsigned */);
            else if (std::optional<int64_t> s = value.getAsInteger ())
              n = APSInt (APInt (64, static_cast<uint64_t> (*s), true), false);
            else
              fail ("enumerator value must be an integer");

            EnumeratorRecord m (MemberAccess::Public, n, text (f, "name"));
            b.writeMemberType (m);
          }
          else
            fail ("unknown field kind " + kind);
        }

        r = table_.insertRecord (b);
      }
      else if (leaf == "struct" || leaf == "union")
      {
        StringRef name (text (o, "name"));
        bool forward (boolean (o, "forward"));

        // A forward reference names the type and nothing else; debuggers
        // find the definition through the TPI hash of that name.
        //
        ClassOptions options (forward ? ClassOptions::ForwardReference : ClassOptions::None);
        TypeIndex fields;
        uint16_t count (0);
        uint64_t size (0);

        if (!forward)
        {
          fields = reference (o, "fields");
          if (!is (fields, LF_FIELDLIST))
            fail (name + ": fields must refer to a field list");

          count = static_cast<uint16_t> (unsigned_integer (o, "count", 0xffff));
          size = uint32 (o, "size");
        }

        if (leaf == "struct")
        {
          ClassRecord t (TypeRecordKind::Struct, count, options, fields,
                         TypeIndex (), TypeIndex (), size, name, "");
          r = table_.writeLeafType (t);
        }
        else
        {
          UnionRecord t (count, options, fields, size, name, "");
          r = table_.writeLeafType (t);
        }
      }
      else if (leaf == "enum")
      {
        TypeIndex fields (reference (o, "fields"));
        if (!is (fields, LF_FIELDLIST))
          fail ("enum fields must refer to a field list");

        EnumRecord t (static_cast<uint16_t> (unsigned_integer (o, "count", 0xffff)),
                      ClassOptions::None,
                      fields,
                      text (o, "name"),
                      "",
                      reference (o, "underlying"));
        r = table_.writeLeafType (t);
      }
      else
        fail ("unknown type record leaf " + leaf);

      indexes_.push_back (r);
    }

    ArrayRef<ArrayRef<uint8_t>>
    records () const
    {
      return table_.records ();
    }

  private:
    AppendingTypeTableBuilder table_;
    std::vector<TypeIndex> indexes_;
  };
}

int
main (int argc, char* argv[])
{
  if (argc != 4)
  {
    errs () << "usage: ida2pdb-pdbgen <exe> <input.json> <out.pdb>\n";
    return 2;
  }

  // The PDB writer hashes and sorts through llvm::parallel, whose thread pool
  // is torn down when libLLVM unloads, and on Windows that teardown never
  // finishes, so the process hangs on exit with the PDB already written. One
  // thread never starts the pool, and the whole run takes seconds anyway.
  //
  parallel::strategy = hardware_concurrency (1);

  image exe (read_image (argv[1]));

  std::unique_ptr<MemoryBuffer> input_buffer (
    check (errorOrToExpected (MemoryBuffer::getFile (argv[2]))));
  json::Value input_value (check (json::parse (input_buffer->getBuffer ())));
  const json::Object& input (as_object (input_value, "input"));

  BumpPtrAllocator alloc;

  // Types.
  //
  type_table types (alloc);
  for (const json::Value& v: array (input, "types"))
    types.add (as_object (v, "type record"));

  PDBFileBuilder builder (alloc);
  check (builder.initialize (4096));

  for (uint32_t i (0); i != uint32_t (SpecialStream::kSpecialStreamCount); ++i)
    check (builder.getMsfBuilder ().addStream (0));

  InfoStreamBuilder& info (builder.getInfoBuilder ());
  info.setVersion (PdbRaw_ImplVer::PdbImplVC70);
  info.setAge (exe.age);
  info.setSignature (exe.signature);
  info.setGuid (exe.guid);
  info.setHashPDBContentsToGUID (false);
  info.addFeature (PdbRaw_FeatureSig::VC140);

  DbiStreamBuilder& dbi (builder.getDbiBuilder ());
  dbi.setVersionHeader (PdbRaw_DbiVer::PdbDbiV70);
  dbi.setAge (exe.age);
  dbi.setMachineType (exe.machine);
  dbi.setBuildNumber (14, 11);
  dbi.setFlags (DbiFlags::FlagHasCTypesMask);

  TpiStreamBuilder& tpi (builder.getTpiBuilder ());
  TpiStreamBuilder& ipi (builder.getIpiBuilder ());
  tpi.setVersionHeader (PdbRaw_TpiVer::PdbTpiV80);
  ipi.setVersionHeader (PdbRaw_TpiVer::PdbTpiV80);

  for (ArrayRef<uint8_t> rec: types.records ())
    tpi.addTypeRecord (rec, check (hashTypeRecord (CVType (rec))));

  // Procedures. One module holds them all; the globals stream refers to each
  // by its offset in the module's symbol stream, which starts after a 4-byte
  // signature. DIA finds the procedure at an address through the section
  // contributions: it maps the address to a module first, and without a
  // contribution it falls back to the nearest public.
  //
  StringRef module_name (text (input, "module"));
  DbiModuleDescriptorBuilder& module (check (dbi.addModuleInfo (module_name)));
  module.setObjFileName (module_name);

  GSIStreamBuilder& gsi (builder.getGsiBuilder ());
  uint32_t module_offset (4);
  std::vector<SectionContrib> contributions;

  auto contribute ([&] (address a, uint32_t size)
  {
    SectionContrib c {};
    c.ISect = a.segment;
    c.Off = a.offset;
    c.Size = size;
    c.Characteristics = exe.sections[a.segment - 1].Characteristics;
    c.Imod = module.getModuleIndex ();
    contributions.push_back (c);
  });

  auto serialize ([&] (auto& record)
  {
    return SymbolSerializer::writeOneSymbol (record, alloc, CodeViewContainer::Pdb);
  });

  for (const json::Value& v: array (input, "procedures"))
  {
    const json::Object& p (as_object (v, "procedure"));
    StringRef name (text (p, "name"));
    uint32_t size (uint32 (p, "size"));
    address a (exe.at (uint32 (p, "rva"), size, name));

    TypeIndex type (types.reference (p, "type"));
    if (!types.is (type, LF_PROCEDURE))
      fail (name + ": a procedure's type must be a procedure record");

    ProcSym proc (SymbolRecordKind::GlobalProcSym);
    proc.Parent = 0;
    proc.Next = 0;
    proc.CodeSize = size;
    proc.DbgStart = 0;
    proc.DbgEnd = 0;
    proc.FunctionType = type;
    proc.CodeOffset = a.offset;
    proc.Segment = a.segment;
    proc.Flags = ProcSymFlags::None;
    proc.Name = name;

    // The parameters are S_LOCAL records without a location (no S_DEFRANGE
    // follows them), flagged as optimized out: IDA knows their names and
    // types but not where they live during the whole function. dbghelp
    // builds the signature it shows (x module!name) from these, not from the
    // procedure's type.
    //
    std::vector<CVSymbol> params;
    for (const json::Value& v: array (p, "params"))
    {
      const json::Object& o (as_object (v, "parameter"));

      LocalSym local (SymbolRecordKind::LocalSym);
      local.Type = types.reference (o, "type");
      local.Flags = LocalSymFlags::IsParameter | LocalSymFlags::IsOptimizedOut;
      local.Name = text (o, "name", false);
      params.push_back (serialize (local));
    }

    // The procedure's End is the offset of its S_END, after the parameters.
    // It depends on the procedure record's own size: serialize it once to
    // learn that.
    //
    proc.End = 0;
    proc.End = module_offset + serialize (proc).length ();
    for (const CVSymbol& s: params)
      proc.End += s.length ();

    CVSymbol proc_rec (serialize (proc));
    ScopeEndSym end (SymbolRecordKind::ScopeEndSym);
    CVSymbol end_rec (serialize (end));
    module.addSymbol (proc_rec);
    for (const CVSymbol& s: params)
      module.addSymbol (s);
    module.addSymbol (end_rec);
    contribute (a, size);

    ProcRefSym ref (SymbolRecordKind::ProcRefSym);
    ref.SumName = 0;
    ref.SymOffset = module_offset;
    ref.Module = module.getModuleIndex () + 1;
    ref.Name = name;
    gsi.addGlobalSymbol (ref);

    module_offset = proc.End + end_rec.length ();
  }

  std::sort (contributions.begin (), contributions.end (),
             [] (const SectionContrib& x, const SectionContrib& y)
             {
               return std::make_pair (uint16_t (x.ISect), int32_t (x.Off)) <
                      std::make_pair (uint16_t (y.ISect), int32_t (y.Off));
             });

  for (const SectionContrib& c: contributions)
    dbi.addSectionContrib (c);

  // Typed globals and typedefs.
  //
  for (const json::Value& v: array (input, "globals"))
  {
    const json::Object& g (as_object (v, "global"));
    StringRef name (text (g, "name"));
    address a (exe.at (uint32 (g, "rva"), 0, name));

    DataSym d (SymbolRecordKind::GlobalData);
    d.Type = types.reference (g, "type");
    d.DataOffset = a.offset;
    d.Segment = a.segment;
    d.Name = name;
    gsi.addGlobalSymbol (d);
  }

  for (const json::Value& v: array (input, "typedefs"))
  {
    const json::Object& t (as_object (v, "typedef"));

    UDTSym u (SymbolRecordKind::UDTSym);
    u.Type = types.reference (t, "type");
    u.Name = text (t, "name");
    gsi.addGlobalSymbol (serialize (u));
  }

  // Publics: every name, typed or not, so that an address resolves to a name
  // even where no type is known. The names point into the parsed input, which
  // outlives the commit below.
  //
  const json::Array& public_input (array (input, "publics"));
  std::vector<BulkPublic> publics;
  publics.reserve (public_input.size ());

  for (const json::Value& v: public_input)
  {
    const json::Object& p (as_object (v, "public"));
    StringRef name (text (p, "name"));
    address a (exe.at (uint32 (p, "rva"), 0, name));

    BulkPublic b;
    b.Name = name.data ();
    b.NameLen = static_cast<uint32_t> (name.size ());
    b.Segment = a.segment;
    b.Offset = a.offset;
    b.setFlags (boolean (p, "function")
                ? PublicSymFlags::Function | PublicSymFlags::Code
                : PublicSymFlags::None);
    publics.push_back (b);
  }

  gsi.addPublicSymbols (std::move (publics));

  // Debuggers turn section:offset into an address through these.
  //
  ArrayRef<uint8_t> headers (
    reinterpret_cast<const uint8_t*> (exe.sections.data ()),
    exe.sections.size () * sizeof (coff_section));
  check (dbi.addDbgStream (DbgHeaderType::SectionHdr, headers));
  dbi.createSectionMap (exe.sections);

  codeview::GUID guid (exe.guid);
  check (builder.commit (argv[3], &guid));

  outs () << json::Value (json::Object {
    {"type_records", int64_t (types.records ().size ())}}) << '\n';
  return 0;
}
