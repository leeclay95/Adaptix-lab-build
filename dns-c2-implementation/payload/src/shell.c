/*
 * shell.c - Execute a shell command via cmd.exe and capture output
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "protocol.h"

/* -----------------------------------------------------------------------
 * shell_exec
 *
 * Executes "cmd.exe /c <command>" and returns the combined stdout+stderr
 * output as a heap-allocated buffer.  Caller must HeapFree() the result.
 *
 * cmd     : command string (not null-terminated, just bytes)
 * cmd_len : byte length of command
 * out_len : set to output byte count on success
 *
 * Returns NULL on failure.
 * ---------------------------------------------------------------------- */
uint8_t *shell_exec(const uint8_t *cmd, size_t cmd_len, size_t *out_len) {
    /* Build null-terminated command string: "cmd.exe /c <command>" */
    const char *prefix  = "cmd.exe /c ";
    size_t      pfx_len = strlen(prefix);
    size_t      full_len = pfx_len + cmd_len + 1;

    char *full_cmd = (char *)HeapAlloc(GetProcessHeap(), 0, full_len);
    if (!full_cmd) return NULL;

    memcpy(full_cmd, prefix, pfx_len);
    memcpy(full_cmd + pfx_len, cmd, cmd_len);
    full_cmd[pfx_len + cmd_len] = '\0';

    /* Create anonymous pipe for stdout/stderr */
    HANDLE hRead  = NULL;
    HANDLE hWrite = NULL;

    SECURITY_ATTRIBUTES sa;
    memset(&sa, 0, sizeof(sa));
    sa.nLength              = sizeof(sa);
    sa.bInheritHandle       = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        HeapFree(GetProcessHeap(), 0, full_cmd);
        return NULL;
    }

    /* Make the read end non-inheritable */
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    /* Set up STARTUPINFO */
    STARTUPINFOA        si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));

    si.cb         = sizeof(si);
    si.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWrite;
    si.hStdError  = hWrite;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);

    /* CreateProcess */
    BOOL ok = CreateProcessA(
        NULL,        /* lpApplicationName */
        full_cmd,    /* lpCommandLine */
        NULL,        /* lpProcessAttributes */
        NULL,        /* lpThreadAttributes */
        TRUE,        /* bInheritHandles */
        CREATE_NO_WINDOW, /* dwCreationFlags */
        NULL,        /* lpEnvironment */
        NULL,        /* lpCurrentDirectory */
        &si,
        &pi
    );

    HeapFree(GetProcessHeap(), 0, full_cmd);

    if (!ok) {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        return NULL;
    }

    /* Close the write end in the parent so ReadFile can detect EOF */
    CloseHandle(hWrite);

    /* Read all output */
    size_t   buf_cap = 4096;
    size_t   buf_len = 0;
    uint8_t *buf     = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, buf_cap);
    if (!buf) {
        CloseHandle(hRead);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return NULL;
    }

    DWORD bytes_read;
    for (;;) {
        /* Grow buffer if needed */
        if (buf_len + 4096 > buf_cap) {
            size_t   new_cap = buf_cap * 2;
            uint8_t *new_buf = (uint8_t *)HeapReAlloc(GetProcessHeap(), 0, buf, new_cap);
            if (!new_buf) break;
            buf     = new_buf;
            buf_cap = new_cap;
        }

        BOOL rd = ReadFile(hRead, buf + buf_len, 4096, &bytes_read, NULL);
        if (!rd || bytes_read == 0) break;
        buf_len += bytes_read;
    }

    CloseHandle(hRead);
    WaitForSingleObject(pi.hProcess, 10000); /* wait up to 10 s */
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    *out_len = buf_len;
    return buf;
}
