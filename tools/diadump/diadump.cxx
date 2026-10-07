// diadump: print what DIA reads from the PDB of an executable.
//
//   diadump <msdia140.dll> <exe> <pdb directory> [rva ...]
//
// x64dbg reads PDBs through DIA (the msdia140.dll it ships), as does Visual
// Studio. This program loads the given msdia140.dll without COM registration,
// lets it find and match the executable's PDB the way a debugger does (RSDS
// file name, GUID and age, searching only the given directory), and prints
// the publics, procedures, globals, typedefs, structures and enumerations it
// sees, then the symbols DIA finds at each RVA given.
//
// Build it with MSVC and the DIA SDK that Visual Studio installs (from a
// Developer Command Prompt; docs/development.md has the details):
//
//   cl /EHsc /O2 /std:c++17 /I "%VSINSTALLDIR%DIA SDK\include" diadump.cxx ^
//      /link "%VSINSTALLDIR%DIA SDK\lib\amd64\diaguids.lib" ole32.lib oleaut32.lib advapi32.lib

#include <windows.h>
#include <dia2.h>
#include <diacreate.h>

#include <cstdio>
#include <cwchar>
#include <string>
#include <utility>

namespace
{
  // An owning COM interface pointer.
  //
  template <typename T>
  class com
  {
  public:
    com () = default;
    com (const com&) = delete;
    com& operator= (const com&) = delete;
    ~com () {if (p_ != nullptr) p_->Release ();}

    T* operator-> () const {return p_;}
    T* get () const {return p_;}
    T** out () {return &p_;}
    explicit operator bool () const {return p_ != nullptr;}

  private:
    T* p_ = nullptr;
  };

  std::wstring
  take (BSTR b)
  {
    std::wstring r (b != nullptr ? b : L"");
    SysFreeString (b);
    return r;
  }

  std::wstring
  name (IDiaSymbol* s)
  {
    BSTR b (nullptr);
    return s->get_name (&b) == S_OK ? take (b) : L"";
  }

  // Each child of s with the given tag (SymTagNull for all).
  //
  template <typename F>
  void
  children (IDiaSymbol* s, enum SymTagEnum tag, F f)
  {
    com<IDiaEnumSymbols> e;
    if (s->findChildren (tag, nullptr, nsNone, e.out ()) != S_OK)
      return;

    for (;;)
    {
      com<IDiaSymbol> c;
      ULONG n (0);
      if (e->Next (1, c.out (), &n) != S_OK || n != 1)
        break;
      f (c.get ());
    }
  }

  std::wstring
  basic_type (DWORD base, ULONGLONG size)
  {
    std::wstring bits (std::to_wstring (size * 8));
    switch (base)
    {
    case btNoType: return L"<no type>";
    case btVoid:   return L"void";
    case btChar:   return L"char";
    case btWChar:  return L"wchar_t";
    case btChar8:  return L"char8_t";
    case btChar16: return L"char16_t";
    case btChar32: return L"char32_t";
    case btInt:
    case btLong:   return L"int" + bits;
    case btUInt:
    case btULong:  return L"uint" + bits;
    case btFloat:  return L"float" + bits;
    case btBool:   return L"bool" + bits;
    case btHresult: return L"HRESULT";
    default:       return L"<basic " + std::to_wstring (base) + L">";
    }
  }

  std::wstring
  type_name (IDiaSymbol* t)
  {
    if (t == nullptr)
      return L"<none>";

    DWORD tag (0);
    ULONGLONG size (0);
    BOOL is_const (FALSE), is_volatile (FALSE);
    t->get_symTag (&tag);
    t->get_length (&size);
    t->get_constType (&is_const);
    t->get_volatileType (&is_volatile);

    std::wstring r (is_const ? L"const " : L"");
    if (is_volatile)
      r += L"volatile ";

    com<IDiaSymbol> inner;
    switch (tag)
    {
    case SymTagBaseType:
      {
        DWORD base (0);
        t->get_baseType (&base);
        return r + basic_type (base, size);
      }
    case SymTagPointerType:
      t->get_type (inner.out ());
      return r + type_name (inner.get ()) + (size == 4 ? L" *32" : L" *");
    case SymTagArrayType:
      {
        DWORD count (0);
        t->get_count (&count);
        t->get_type (inner.out ());
        return r + type_name (inner.get ()) + L"[" + std::to_wstring (count) + L"]";
      }
    case SymTagFunctionType:
      {
        DWORD cc (0);
        t->get_callingConvention (&cc);
        t->get_type (inner.out ());
        r += type_name (inner.get ()) + L" (cc " + std::to_wstring (cc) + L")(";
        bool first (true);
        children (t, SymTagFunctionArgType, [&] (IDiaSymbol* a)
        {
          com<IDiaSymbol> at;
          a->get_type (at.out ());
          r += (first ? L"" : L", ") + type_name (at.get ());
          first = false;
        });
        return r + L")";
      }
    case SymTagUDT:  return r + L"struct " + name (t);
    case SymTagEnum: return r + L"enum " + name (t);
    default:         return r + name (t) + L" <tag " + std::to_wstring (tag) + L">";
    }
  }

  // The members of a structure or enumeration.
  //
  void
  members (IDiaSymbol* udt)
  {
    children (udt, SymTagData, [] (IDiaSymbol* m)
    {
      LONG offset (0);
      DWORD kind (0), location (0);
      m->get_offset (&offset);
      m->get_dataKind (&kind);
      m->get_locationType (&location);
      com<IDiaSymbol> t;
      m->get_type (t.out ());

      std::wstring extra;
      if (location == LocIsBitField)
      {
        DWORD position (0);
        ULONGLONG width (0);
        m->get_bitPosition (&position);
        m->get_length (&width);
        extra = L" : bits " + std::to_wstring (position) + L"+" + std::to_wstring (width);
      }
      else if (kind == DataIsConstant)
      {
        VARIANT v;
        VariantInit (&v);
        if (m->get_value (&v) == S_OK && VariantChangeType (&v, &v, 0, VT_I8) == S_OK)
          extra = L" = " + std::to_wstring (v.llVal);
        VariantClear (&v);
      }

      if (kind == DataIsConstant)
        std::wprintf (L"    %ls%ls\n", name (m).c_str (), extra.c_str ());
      else
        std::wprintf (L"    +0x%03lx %ls: %ls%ls\n", offset, name (m).c_str (), type_name (t.get ()).c_str (),
                      extra.c_str ());
    });
  }

  void
  list (IDiaSymbol* global, enum SymTagEnum tag, const wchar_t* title, bool details)
  {
    std::wprintf (L"%ls:\n", title);
    children (global, tag, [&] (IDiaSymbol* s)
    {
      DWORD rva (0);
      ULONGLONG size (0);
      BOOL function (FALSE);
      s->get_relativeVirtualAddress (&rva);
      s->get_length (&size);
      s->get_function (&function);
      com<IDiaSymbol> t;
      s->get_type (t.out ());

      wchar_t where[32] = L"";
      if (tag != SymTagUDT && tag != SymTagEnum && tag != SymTagTypedef)
        std::swprintf (where, 32, L" rva 0x%lx", rva);

      std::wstring type (t ? L": " + type_name (t.get ()) : L"");
      std::wprintf (L"  %ls%ls size %llu%ls%ls\n", name (s).c_str (), where, size, type.c_str (),
                    function ? L" (function)" : L"");
      if (details)
        members (s);
    });
  }
}

int
wmain (int argc, wchar_t* argv[])
{
  if (argc < 4)
  {
    std::fwprintf (stderr, L"usage: diadump <msdia140.dll> <exe> <pdb directory> [rva ...]\n");
    return 2;
  }

  CoInitialize (nullptr);

  com<IDiaDataSource> source;
  HRESULT hr (NoRegCoCreate (argv[1], __uuidof (DiaSource), __uuidof (IDiaDataSource),
                             reinterpret_cast<void**> (source.out ())));
  if (FAILED (hr))
  {
    std::fwprintf (stderr, L"diadump: cannot load DIA from %ls: 0x%lx\n", argv[1], hr);
    return 1;
  }

  // loadDataForExe also looks next to the executable and at the RSDS path:
  // keep a stale PDB away from both when checking another one.
  //
  hr = source->loadDataForExe (argv[2], argv[3], nullptr);
  if (FAILED (hr))
  {
    std::fwprintf (stderr, L"diadump: no matching PDB for %ls: 0x%lx\n", argv[2], hr);
    return 1;
  }

  com<IDiaSession> session;
  com<IDiaSymbol> global;
  source->openSession (session.out ());
  session->get_globalScope (global.out ());

  DWORD age (0);
  global->get_age (&age);
  std::wprintf (L"matched %ls, age %lu\n", name (global.get ()).c_str (), age);

  list (global.get (), SymTagPublicSymbol, L"publics", false);
  list (global.get (), SymTagFunction, L"functions", false);
  list (global.get (), SymTagData, L"globals", false);
  list (global.get (), SymTagTypedef, L"typedefs", false);
  list (global.get (), SymTagUDT, L"structures", true);
  list (global.get (), SymTagEnum, L"enumerations", true);

  for (int i (4); i < argc; ++i)
  {
    DWORD rva (static_cast<DWORD> (std::wcstoul (argv[i], nullptr, 0)));
    for (auto [tag, what]: {std::pair {SymTagFunction, L"function"}, std::pair {SymTagNull, L"any"}})
    {
      com<IDiaSymbol> s;
      LONG displacement (0);
      if (session->findSymbolByRVAEx (rva, tag, s.out (), &displacement) == S_OK && s)
        std::wprintf (L"rva 0x%lx, %ls: %ls+0x%lx\n", rva, what, name (s.get ()).c_str (), displacement);
      else
        std::wprintf (L"rva 0x%lx, %ls: none\n", rva, what);
    }
  }

  return 0;
}
