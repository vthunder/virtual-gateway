# virtual-gateway

In-browser TCP/IP gateway for Mac OS 8 emulation via [infinite-mac](https://github.com/mihaip/infinite-mac).

Replaces the Node.js WebSocket server (`server.js`) with a pure TypeScript module that runs inside the Cloudflare Worker / browser context — no server required.

## Architecture

```
[ Mac OS 8 → Open Transport → WASM → JS ethernet driver ]
                                          |
                               JSVirtualGatewayProvider
                                          |
                     ┌──────────────────┼──────────────────┐
                     ▼                  ▼                  ▼
                ARP handler       DHCP handler        DNS handler
                                          |
                                  TCP state machine
                                          |
                            ┌─────────────┴─────────────┐
                            ▼                           ▼
                     HTTP handler                 /nav/ interceptor
                            |                           |
                fetch() → WebOne proxy          window.parent.postMessage
```

## Virtual Network

| | Value |
|---|---|
| Mac IP | 10.0.0.2 |
| Gateway IP | 10.0.0.1 |
| Gateway MAC | b2:00:00:00:00:01 |
| Subnet | 255.255.255.0 |

## Usage in infinite-mac

Add `?ethernet_gw=https://sandmill-proxy.sandmill.org` to the emulator URL.

The `JSVirtualGatewayProvider` is wired in `src/defs/run-def.ts`:

```typescript
const ethernetGw = searchParams.get("ethernet_gw");
if (ethernetGw) {
  ethernetProvider = new JSVirtualGatewayProvider(ethernetGw);
}
```

## Build

```bash
npm install
npm run build   # outputs to dist/
```

## Legacy Node.js server

`server.js` is the original WebSocket reference implementation. It remains in the repo for reference and as a fallback during cutover.
