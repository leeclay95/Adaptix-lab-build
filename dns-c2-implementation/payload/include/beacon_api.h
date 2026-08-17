#ifndef BEACON_API_H
#define BEACON_API_H

#include <windows.h>
#include <stdint.h>

/* ---- Output type constants ---- */
#define CALLBACK_OUTPUT       0x0
#define CALLBACK_ERROR        0xd
#define CALLBACK_OUTPUT_OEM   0x1e
#define CALLBACK_OUTPUT_UTF8  0x20

/* ---- Beacon data parser (input args) ---- */
typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} datap;

/* ---- Beacon format buffer (output builder) ---- */
typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} formatp;

/* ---- Global BOF output accumulator ---- */
extern uint8_t *g_bof_output;
extern size_t   g_bof_output_len;
extern size_t   g_bof_output_cap;

/* ---- Output ---- */
void  BeaconOutput(int type, char *data, int len);
void  BeaconPrintf(int type, char *fmt, ...);

/* ---- Data parser ---- */
void  BeaconDataParse(datap *parser, char *buffer, int size);
char *BeaconDataExtract(datap *parser, int *size);
int   BeaconDataInt(datap *parser);
short BeaconDataShort(datap *parser);
int   BeaconDataLength(datap *parser);

/* ---- Format buffer ---- */
void  BeaconFormatAlloc(formatp *fmt, int maxsz);
void  BeaconFormatReset(formatp *fmt);
void  BeaconFormatFree(formatp *fmt);
void  BeaconFormatAppend(formatp *fmt, char *text, int len);
void  BeaconFormatPrintf(formatp *fmt, char *format, ...);
void  BeaconFormatInt(formatp *fmt, int val);
char *BeaconFormatToString(formatp *fmt, int *size);

/* ---- Key-value store ---- */
BOOL  BeaconAddValue(const char *key, void *ptr);
void *BeaconGetValue(const char *key);
BOOL  BeaconRemoveValue(const char *key);

/* ---- Token / process helpers ---- */
int   BeaconIsAdmin(void);
BOOL  BeaconUseToken(HANDLE token);
void  BeaconRevertToken(void);
BOOL  BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken,
                                  STARTUPINFO *si, PROCESS_INFORMATION *pi);
void  BeaconInjectProcess(HANDLE hProc, int pid, char *payload, int p_len,
                          int p_offset, char *arg, int a_len);
void  BeaconInjectTemporaryProcess(PROCESS_INFORMATION *pi, char *payload,
                                   int p_len, int p_offset,
                                   char *arg, int a_len);
void  BeaconCleanupProcess(PROCESS_INFORMATION *pi);
BOOL  toWideChar(char *src, wchar_t *dst, int max);

#endif
