# virtual-ethernet-switch

A WebSocket server that acts as a virtual network gateway for the [Infinite Mac](https://infinitemac.org) emulator. Enables Mac OS 8 to browse the modern web through Netscape Navigator.

## What it does

- **ARP**: Responds to "who has 10.0.0.1?" with the gateway MAC address
- **DHCP**: Hands out IP config to the Mac (10.0.0.2, gateway 10.0.0.1, DNS 10.0.0.1)
- **DNS**: Resolves hostnames by forwarding to 8.8.8.8
- **ICMP**: Responds to pings (needed for Open Transport to confirm gateway reachability)
- **TCP + HTTP/1.0 proxy**: Accepts TCP connections from Netscape, fetches pages via a retro HTTP proxy, returns HTTP/1.0 responses

## Configuration

| Env var | Default | Description |
|---|---|---|
| `PORT` | `3001` | WebSocket server port |
| `CHECKPOINT` | `4` | Feature level (2=ARP, 3=TCP, 4=HTTP proxy) |
| `RETRO_PROXY_URL` | `http://127.0.0.1:8118` | URL of the retro HTTP proxy (WebOne or compatible) |

For production, set `RETRO_PROXY_URL` to the deployed sandmill-proxy URL, e.g. `http://proxy.sandmill.org:8080`.

## Virtual network

```
Mac IP:      10.0.0.2
Gateway IP:  10.0.0.1  (this server)
Gateway MAC: 02:00:00:00:00:01
Subnet:      255.255.255.0
DNS:         10.0.0.1
```

## Local development

```bash
npm install
npm run proxy   # start with full HTTP proxy (checkpoint 4)
```

Environment:
- `PORT` — WebSocket port (default: 3001)
- `CHECKPOINT` — 2=ARP only, 3=TCP passthrough, 4=full HTTP proxy
- `RETRO_PROXY_URL` — retro proxy URL (default: `http://127.0.0.1:8118`)

## Production (Docker)

```bash
docker build -t virtual-ethernet-switch .
docker run -p 3001:3001 virtual-ethernet-switch
```

The Dockerfile is Node 20 only. Set `RETRO_PROXY_URL` to point at an external retro proxy.

## Architecture

```
Browser (Mac OS 8 emulator)
    │ WebSocket
    ▼
Cloudflare Worker (ethernet zone relay)
    │ WebSocket
    ▼
virtual-ethernet-switch  ← this repo
    │ HTTP forward proxy (RETRO_PROXY_URL)
    ▼
sandmill-proxy (external)
    │ HTTPS downgrade + image resize
    ▼
Real internet
```
