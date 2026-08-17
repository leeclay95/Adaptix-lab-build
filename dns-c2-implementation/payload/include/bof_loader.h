#ifndef BOF_LOADER_H
#define BOF_LOADER_H

#include <windows.h>
#include <stdint.h>

/*
 * Load and execute a COFF BOF in-process.
 * Calls the exported "go" symbol with (args, args_len).
 * Captures all BeaconOutput() calls into a heap buffer.
 *
 * Returns the output buffer (caller must HeapFree).
 * *out_len is set to the number of output bytes.
 * Returns NULL on failure.
 */
uint8_t *bof_execute(const uint8_t *coff_data, size_t coff_len,
                     const uint8_t *args,       size_t args_len,
                     size_t *out_len);

#endif
