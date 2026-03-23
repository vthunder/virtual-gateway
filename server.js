#!/usr/bin/env node
/**
 * Sandmill Ethernet Server — Checkpoints 2+
 *
 * A WebSocket server that acts as a virtual network for Infinite Mac.
 * Builds progressively on the tap: adds ARP responses, then TCP/HTTP proxy.
 *
 * Usage:
 *   npm install ws node-fetch   # node-fetch only needed for HTTP proxy
 *   node ethernet-server.js [port]
 *
 * Network config (what the Mac will see):
 *   Mac IP:      10.0.0.2
 *   Gateway IP:  10.0.0.1  (this server)
 *   Gateway MAC: 02:00:00:00:00:01
 *   Subnet:      255.255.255.0
 *   DNS:         10.0.0.1  (we intercept port 53 queries)
 *
 * Configure Mac OS 8 Open Transport:
 *   TCP/IP control panel → Manual, IP 10.0.0.2, mask 255.255.255.0, gateway 10.0.0.1
 *
 * Checkpoints enabled by this file:
 *   CHECKPOINT=2 → ARP only (Mac sees "network connected")
 *   CHECKPOINT=3 → TCP passthrough (raw relay to upstream)
 *   CHECKPOINT=4 → HTTP proxy (parse HTTP/1.0, fetch, respond)  [default]
 */

const { WebSocketServer } = require('ws');
const http = require('http');
const https = require('https');
const net = require('net');

const PORT = parseInt(process.argv[2] || '3001', 10);
const CHECKPOINT = parseInt(process.env.CHECKPOINT || '4', 10);

// ── Virtual network constants ─────────────────────────────────────────────────

const GW_IP   = '10.0.0.1';
const MAC_IP  = '10.0.0.2';
const GW_MAC  = [0xb2, 0x00, 0x00, 0x00, 0x00, 0x01];
const BCAST   = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

function ipBytes(ip) {
  return ip.split('.').map(Number);
}
function macToString(b, o) {
  return Array.from(b.slice(o, o + 6)).map(x => x.toString(16).padStart(2,'0')).join(':');
}
function ipToString(b, o) {
  return `${b[o]}.${b[o+1]}.${b[o+2]}.${b[o+3]}`;
}

// ── Frame builders ────────────────────────────────────────────────────────────

function buildEthernetFrame(dstMac, srcMac, etherType, payload) {
  const frame = Buffer.alloc(14 + payload.length);
  dstMac.forEach((b, i) => frame[i] = b);
  srcMac.forEach((b, i) => frame[6 + i] = b);
  frame[12] = (etherType >> 8) & 0xff;
  frame[13] = etherType & 0xff;
  payload.copy(frame, 14);
  return frame;
}

function buildArpReply(requestBytes) {
  // ARP request: offset 0 in payload (after Ethernet header)
  // sha=sender hardware, spa=sender proto, tha=target hardware, tpa=target proto
  const senderMac = requestBytes.slice(8, 14);   // sha — Mac's MAC
  const senderIp  = requestBytes.slice(14, 18);  // spa — Mac's IP
  const targetIp  = requestBytes.slice(24, 28);  // tpa — requested IP (should be GW)

  const arpReply = Buffer.alloc(28);
  arpReply[0] = 0; arpReply[1] = 1;    // htype: Ethernet
  arpReply[2] = 8; arpReply[3] = 0;    // ptype: IPv4
  arpReply[4] = 6;                      // hlen
  arpReply[5] = 4;                      // plen
  arpReply[6] = 0; arpReply[7] = 2;    // op: reply

  // sha: our MAC (gateway)
  GW_MAC.forEach((b, i) => arpReply[8 + i] = b);
  // spa: our IP (gateway)
  ipBytes(GW_IP).forEach((b, i) => arpReply[14 + i] = b);
  // tha: Mac's MAC
  senderMac.copy(arpReply, 18);
  // tpa: Mac's IP
  senderIp.copy(arpReply, 24);

  return buildEthernetFrame(
    Array.from(senderMac),
    GW_MAC,
    0x0806,
    arpReply
  );
}

// ── pingPING builder (emulator-level probe) ───────────────────────────────────

// Sends an emulator-level pingPING frame (etherType=0xc, payload "pingPING"+timestamp).
// The emulator worker's handlePingPacket() will intercept this and send back a pingPONG!
// This lets us test whether our outbound frames reach the emulator without needing the IP stack.
function sendEmulatorPing(ws, macSrcMac, connId = '?') {
  // ETHERNET_PING_HEADER = "pingPING" = [112, 105, 110, 103, 80, 73, 78, 71]
  const pingHeader = Buffer.from([112, 105, 110, 103, 80, 73, 78, 71]);
  const tsBuf = Buffer.alloc(4);
  tsBuf.writeUInt32BE(Date.now() & 0xffffffff, 0);
  const payload = Buffer.concat([pingHeader, tsBuf]);
  const frame = buildEthernetFrame(
    [0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // broadcast dst
    GW_MAC,
    0x000c,
    payload
  );
  try {
    ws.send(JSON.stringify({ type: 'receive', packetArray: Array.from(frame) }));
    console.log(`${ts()} #${connId} PING sent  (expect PONG)`);
  } catch (e) {
    console.error(`${ts()} #${connId} PING failed: ${e.message}`);
  }
}

// ── ICMP builder ─────────────────────────────────────────────────────────────

function sendIcmpPing(ws, macSrcMac) {
  // ICMP echo request to MAC_IP (10.0.0.2) from GW_IP (10.0.0.1)
  const icmpPayload = Buffer.alloc(8); // 4-byte header (type+code+checksum) + 4-byte id+seq
  icmpPayload[0] = 8;   // type: echo request
  icmpPayload[1] = 0;   // code
  icmpPayload[2] = 0; icmpPayload[3] = 0;   // checksum placeholder
  icmpPayload[4] = 0; icmpPayload[5] = 1;   // identifier
  icmpPayload[6] = 0; icmpPayload[7] = 1;   // sequence
  const csum = ipChecksum(icmpPayload);
  icmpPayload[2] = (csum >> 8) & 0xff;
  icmpPayload[3] = csum & 0xff;

  const ipLen = 20 + icmpPayload.length;
  const ip = Buffer.alloc(ipLen);
  ip[0] = 0x45; ip[1] = 0;
  ip.writeUInt16BE(ipLen, 2);
  ip.writeUInt16BE(0x1234, 4); // ID
  ip.writeUInt16BE(0, 6);
  ip[8] = 64; ip[9] = 1; // TTL, proto ICMP
  ip.writeUInt16BE(0, 10);
  ipBytes(GW_IP).forEach((b, i) => ip[12 + i] = b);
  ipBytes(MAC_IP).forEach((b, i) => ip[16 + i] = b);
  ip.writeUInt16BE(ipChecksum(ip.slice(0, 20)), 10);
  icmpPayload.copy(ip, 20);

  const frame = buildEthernetFrame(Array.from(macSrcMac), GW_MAC, 0x0800, ip);
  try {
    ws.send(JSON.stringify({ type: 'receive', packetArray: Array.from(frame) }));
    console.log(`${ts()} ICMP echo request sent to ${MAC_IP}`);
  } catch (e) {
    console.error(`${ts()} ICMP send failed: ${e.message}`);
  }
}

// ── IP / TCP builders ─────────────────────────────────────────────────────────

function ipChecksum(buf) {
  let sum = 0;
  for (let i = 0; i < buf.length; i += 2) {
    sum += (buf[i] << 8) | (i + 1 < buf.length ? buf[i + 1] : 0);
  }
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return ~sum & 0xffff;
}

function tcpChecksum(srcIp, dstIp, tcpSegment) {
  // Pseudo-header: srcIp(4) dstIp(4) zero(1) proto(1) tcpLen(2)
  const pseudo = Buffer.alloc(12 + tcpSegment.length);
  ipBytes(srcIp).forEach((b, i) => pseudo[i] = b);
  ipBytes(dstIp).forEach((b, i) => pseudo[4 + i] = b);
  pseudo[8] = 0;
  pseudo[9] = 6; // TCP
  pseudo[10] = (tcpSegment.length >> 8) & 0xff;
  pseudo[11] = tcpSegment.length & 0xff;
  tcpSegment.copy(pseudo, 12);
  return ipChecksum(pseudo);
}

function buildIpTcpPacket({ srcIp, dstIp, srcPort, dstPort, seq, ack, flags, data }) {
  const tcpLen = 20 + data.length;
  const tcp = Buffer.alloc(tcpLen);
  tcp.writeUInt16BE(srcPort, 0);
  tcp.writeUInt16BE(dstPort, 2);
  tcp.writeUInt32BE(seq >>> 0, 4);
  tcp.writeUInt32BE(ack >>> 0, 8);
  tcp[12] = 0x50; // data offset: 5 * 4 = 20 bytes
  tcp[13] = flags;
  tcp.writeUInt16BE(65535, 14); // window
  tcp.writeUInt16BE(0, 16);     // checksum placeholder
  tcp.writeUInt16BE(0, 18);     // urgent
  data.copy(tcp, 20);

  const csum = tcpChecksum(srcIp, dstIp, tcp);
  tcp.writeUInt16BE(csum, 16);

  const ipLen = 20 + tcpLen;
  const ip = Buffer.alloc(ipLen);
  ip[0] = 0x45;                          // version + IHL
  ip[1] = 0;                             // DSCP
  ip.writeUInt16BE(ipLen, 2);
  ip.writeUInt16BE(Math.random() * 65535 | 0, 4); // ID
  ip.writeUInt16BE(0, 6);               // flags + frag offset
  ip[8] = 64;                            // TTL
  ip[9] = 6;                             // protocol: TCP
  ip.writeUInt16BE(0, 10);              // checksum placeholder
  ipBytes(srcIp).forEach((b, i) => ip[12 + i] = b);
  ipBytes(dstIp).forEach((b, i) => ip[16 + i] = b);
  const icsum = ipChecksum(ip.slice(0, 20));
  ip.writeUInt16BE(icsum, 10);
  tcp.copy(ip, 20);

  return ip;
}

// ── TCP connection state ──────────────────────────────────────────────────────

const TCP_FLAGS = {
  FIN: 0x01,
  SYN: 0x02,
  RST: 0x04,
  PSH: 0x08,
  ACK: 0x10,
};

class TcpConnection {
  constructor({ ws, srcIp, srcPort, dstIp, dstPort, macSrcMac, retroBase }) {
    this.ws = ws;            // WebSocket to send replies back to Mac
    this.srcIp = srcIp;      // Mac's IP
    this.srcPort = srcPort;  // Mac's source port
    this.dstIp = dstIp;      // Destination IP (where Mac wants to connect)
    this.dstPort = dstPort;  // Destination port
    this.macSrcMac = macSrcMac; // Mac's hardware address (for Ethernet frame)
    this.retroBase = retroBase; // Base URL for the retro proxy (derived from WS host)

    this.state = 'SYN_RECEIVED';
    this.serverSeq = (Math.random() * 0x7fffffff | 0) >>> 0;
    this.clientSeq = 0;     // set when SYN received
    this.recvBuf = Buffer.alloc(0);
    this.httpHandled = false;
  }

  // Send an IP packet back to the Mac
  send(flags, data = Buffer.alloc(0)) {
    const ipPacket = buildIpTcpPacket({
      srcIp: GW_IP,
      dstIp: this.srcIp,
      srcPort: this.dstPort,
      dstPort: this.srcPort,
      seq: this.serverSeq,
      ack: this.clientSeq,
      flags,
      data,
    });
    const frame = buildEthernetFrame(
      Array.from(this.macSrcMac),
      GW_MAC,
      0x0800,
      ipPacket
    );
    const msg = JSON.stringify({
      type: 'receive',
      packetArray: Array.from(frame),
    });
    this.ws.send(msg);
    const flagNames = Object.entries(TCP_FLAGS).filter(([,v]) => flags & v).map(([k]) => k).join('|');
    console.log(`${ts()} [→mac] TCP  ${flagNames.padEnd(11)} ${GW_IP}:${this.dstPort}→${this.srcIp}:${this.srcPort}  seq=${this.serverSeq}  ack=${this.clientSeq}${data.length > 0 ? `  data=${data.length}b` : ''}`);
    if (data.length > 0) this.serverSeq = (this.serverSeq + data.length) >>> 0;
  }
}

// ── HTTP proxy ────────────────────────────────────────────────────────────────

function fetchHttp(method, url, headers, body, _redirects = 0) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: method || 'GET',
      headers: {
        'User-Agent': 'Mozilla/2.02 (Macintosh; I; PPC)',
        'Host': parsed.host,
        ...headers,
      },
    };
    const req = lib.request(options, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && _redirects < 5) {
        const next = new URL(res.headers.location, url).href;
        res.resume(); // drain and discard
        resolve(fetchHttp(method, next, headers, body, _redirects + 1));
        return;
      }
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

const RETRO_PROXY_URL = process.env.RETRO_PROXY_URL || 'http://127.0.0.1:8118';

function fetchViaProxy(url, reqHeaders) {
  return new Promise((resolve, reject) => {
    const proxyUrl = new URL(RETRO_PROXY_URL);

    const isHttps = proxyUrl.protocol === 'https:';
    const defaultPort = isHttps ? 443 : 80;
    const options = {
      hostname: proxyUrl.hostname,
      port: parseInt(proxyUrl.port || String(defaultPort), 10),
      // Forward proxy protocol: absolute URI as the path
      path: url,
      method: 'GET',
      headers: {
        'Host': new URL(url).host,
        'User-Agent': (reqHeaders && reqHeaders['user-agent']) || 'Mozilla/2.02 (Macintosh; I; PPC)',
        'Accept': (reqHeaders && reqHeaders['accept']) || '*/*',
      },
    };

    const transport = isHttps ? https : http;
    const req = transport.request(options, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks),
      }));
    });
    req.on('error', reject);
    req.end();
  });
}

function parseHttpRequest(buf) {
  const str = buf.toString('latin1');
  const headerEnd = str.indexOf('\r\n\r\n');
  if (headerEnd === -1) return null; // incomplete
  const headerSection = str.slice(0, headerEnd);
  const lines = headerSection.split('\r\n');
  const [method, path, version] = lines[0].split(' ');
  const headers = {};
  for (let i = 1; i < lines.length; i++) {
    const colon = lines[i].indexOf(':');
    if (colon !== -1) {
      headers[lines[i].slice(0, colon).toLowerCase()] = lines[i].slice(colon + 2).trim();
    }
  }
  const bodyStart = headerEnd + 4;
  const contentLength = parseInt(headers['content-length'] || '0', 10);
  if (buf.length < bodyStart + contentLength) return null; // incomplete body
  return { method, path, version, headers, body: buf.slice(bodyStart, bodyStart + contentLength) };
}

async function handleHttpRequest(conn, scheme = 'http') {
  if (conn.httpHandled) return;
  conn.httpHandled = true;

  const req = parseHttpRequest(conn.recvBuf);
  if (!req) {
    console.log(`${ts()} HTTP incomplete request from ${conn.srcIp}:${conn.srcPort}  → RST`);
    conn.send(TCP_FLAGS.RST);
    return;
  }

  const host = req.headers['host'] || conn.dstIp;
  const url = `${scheme}://${host}${req.path}`;

  // Navigation intercept: GET http://10.0.0.1/nav/<path>
  // Reply with a 200 OK to the Mac (so OT/Netscape doesn't hang),
  // then send a {"type":"nav"} WebSocket message so the browser page can navigate.
  if (conn.dstIp === GW_IP && req.path.startsWith('/nav/')) {
    const navPath = '/' + req.path.slice(5); // /nav/blog → /blog
    console.log(`${ts()} HTTP ${req.method} /nav${navPath}  → nav redirect`);
    const body = Buffer.from(`<html><body>Navigating to ${navPath}...</body></html>`);
    const headers = [
      `HTTP/1.0 200 OK`,
      `Content-Length: ${body.length}`,
      `Content-Type: text/html`,
      `Connection: close`,
      '', '',
    ].join('\r\n');
    const full = Buffer.concat([Buffer.from(headers), body]);
    conn.send(TCP_FLAGS.ACK | TCP_FLAGS.PSH, full);
    conn.send(TCP_FLAGS.FIN | TCP_FLAGS.ACK);
    conn.state = 'FIN_SENT';
    // Notify the browser to navigate
    conn.ws.send(JSON.stringify({ type: 'nav', path: navPath }));
    return;
  }

  // Since DNS resolves ALL hostnames to GW_IP, we must use the Host header to distinguish:
  // - Host is GW_IP or absent → request to the virtual gateway itself → serve local page
  // - Host is a real hostname → proxy through the sandmill.org retro endpoint
  const hostHeader = (req.headers['host'] || '').split(':')[0];
  const isGatewayRequest = !req.headers['host'] || hostHeader === GW_IP;

  if (isGatewayRequest) {
    console.log(`${ts()} HTTP ${req.method} ${url}  (gateway)`);
    const body = Buffer.from([
      '<html><head><title>Sandmill Gateway</title></head><body>',
      '<h2>Sandmill Gateway</h2>',
      '<p>You are connected to the Sandmill ethernet gateway.</p>',
      '<p>Try: <a href="http://sandmill.org/">http://sandmill.org/</a></p>',
      '</body></html>',
    ].join(''));
    const headers = [
      'HTTP/1.0 200 OK',
      `Content-Length: ${body.length}`,
      'Content-Type: text/html',
      'Connection: close',
      '', '',
    ].join('\r\n');
    conn.send(TCP_FLAGS.ACK | TCP_FLAGS.PSH, Buffer.concat([Buffer.from(headers), body]));
    conn.send(TCP_FLAGS.FIN | TCP_FLAGS.ACK);
    conn.state = 'FIN_SENT';
    return;
  }

  // Real hostname — forward to retro proxy (RETRO_PROXY_URL).
  // The proxy handles HTTPS→HTTP/1.0 downgrade, image resizing, redirect following.
  let responseBody, statusCode, statusText, contentType;
  try {
    const result = await fetchViaProxy(url, req.headers);
    statusCode = result.status;
    statusText = http.STATUS_CODES[statusCode] || 'Unknown';
    responseBody = result.body;
    contentType = result.headers['content-type'] || 'application/octet-stream';

    console.log(`${ts()} HTTP ${req.method} ${url}  → ${statusCode} ${statusText}  ${responseBody.length}b  ${contentType}`);
  } catch (e) {
    console.error(`${ts()} HTTP fetch error: ${e.message}`);
    statusCode = 502;
    statusText = 'Bad Gateway';
    contentType = 'text/html';
    responseBody = Buffer.from(`<html><body>Proxy error: ${e.message}</body></html>`);
  }

  const responseHeaders = [
    `HTTP/1.0 ${statusCode} ${statusText}`,
    `Content-Length: ${responseBody.length}`,
    `Content-Type: ${contentType}`,
    `Connection: close`,
    '',
    '',
  ].join('\r\n');

  const full = Buffer.concat([Buffer.from(responseHeaders), responseBody]);

  // Send in chunks to respect TCP window
  const CHUNK = 1460; // MSS
  for (let offset = 0; offset < full.length; offset += CHUNK) {
    const chunk = full.slice(offset, offset + CHUNK);
    conn.send(TCP_FLAGS.ACK | TCP_FLAGS.PSH, chunk);
  }
  conn.send(TCP_FLAGS.FIN | TCP_FLAGS.ACK);
  conn.state = 'FIN_SENT';
}

// ── ICMP / DNS / DHCP handlers ────────────────────────────────────────────────

function sendIcmpEchoReply(ws, ipPayload, ihl, srcIp, srcMac, connId = '?') {
  const icmpData = ipPayload.slice(ihl);
  const reply = Buffer.alloc(icmpData.length);
  icmpData.copy(reply);
  reply[0] = 0; // type: echo reply
  reply[1] = 0; // code
  reply[2] = 0; reply[3] = 0; // zero checksum
  const csum = ipChecksum(reply);
  reply[2] = (csum >> 8) & 0xff;
  reply[3] = csum & 0xff;

  const ipLen = 20 + reply.length;
  const ip = Buffer.alloc(ipLen);
  ip[0] = 0x45;
  ip.writeUInt16BE(ipLen, 2);
  ip.writeUInt16BE(ipPayload.readUInt16BE(4), 4); // same IP ID
  ip[8] = 64; ip[9] = 1; // TTL, proto ICMP
  ipBytes(GW_IP).forEach((b, i) => { ip[12 + i] = b; });
  ipBytes(srcIp).forEach((b, i) => { ip[16 + i] = b; });
  ip.writeUInt16BE(ipChecksum(ip.slice(0, 20)), 10);
  reply.copy(ip, 20);

  const frame = buildEthernetFrame(Array.from(srcMac), GW_MAC, 0x0800, ip);
  ws.send(JSON.stringify({ type: 'receive', packetArray: Array.from(frame) }));
  console.log(`${ts()} #${connId} ICMP echo ${srcIp} → ${GW_IP}  → replied`);
}

// DNS: reply to any A query with GW_IP so all hostnames resolve through our proxy.
function buildDnsAReply(dnsQuery) {
  if (dnsQuery.length < 12) return null;
  const txId = dnsQuery.readUInt16BE(0);
  const qdCount = dnsQuery.readUInt16BE(4);
  if (qdCount < 1) return null;

  // Walk QNAME (label encoding: length-byte, then that many chars, 0-terminated)
  let pos = 12;
  while (pos < dnsQuery.length) {
    const llen = dnsQuery[pos];
    if (llen === 0) { pos++; break; }
    if ((llen & 0xc0) === 0xc0) { pos += 2; break; } // pointer
    pos += 1 + llen;
  }
  if (pos + 4 > dnsQuery.length) return null;
  const qtype  = dnsQuery.readUInt16BE(pos);
  pos += 4; // skip QTYPE + QCLASS

  // Only handle A (1) and ANY (255) queries; for others return NOERROR with 0 answers
  const anCount = (qtype === 1 || qtype === 255) ? 1 : 0;
  const questionBytes = dnsQuery.slice(12, pos);

  const reply = Buffer.alloc(12 + questionBytes.length + (anCount ? 16 : 0));
  reply.writeUInt16BE(txId, 0);
  reply.writeUInt16BE(0x8180, 2); // QR=1 AA=1 RD=1 RA=1 RCODE=0
  reply.writeUInt16BE(qdCount, 4);
  reply.writeUInt16BE(anCount, 6);
  reply.writeUInt16BE(0, 8);
  reply.writeUInt16BE(0, 10);
  questionBytes.copy(reply, 12);

  if (anCount) {
    let a = 12 + questionBytes.length;
    reply.writeUInt16BE(0xc00c, a); a += 2; // name ptr
    reply.writeUInt16BE(1, a); a += 2;      // TYPE A
    reply.writeUInt16BE(1, a); a += 2;      // CLASS IN
    reply.writeUInt32BE(300, a); a += 4;    // TTL 300s
    reply.writeUInt16BE(4, a); a += 2;      // RDLENGTH
    ipBytes(GW_IP).forEach((b, i) => { reply[a + i] = b; });
  }
  return reply;
}

function sendDnsReply(ws, udpSeg, srcIp, srcPort, srcMac, connId = '?') {
  const dnsQuery = udpSeg.slice(8); // past UDP header
  const qname = dnsExtractQname(dnsQuery);
  const dnsReply = buildDnsAReply(dnsQuery);
  if (!dnsReply) return;

  const udpLen = 8 + dnsReply.length;
  const udp = Buffer.alloc(udpLen);
  udp.writeUInt16BE(53, 0);
  udp.writeUInt16BE(srcPort, 2);
  udp.writeUInt16BE(udpLen, 4);
  udp.writeUInt16BE(0, 6); // checksum optional
  dnsReply.copy(udp, 8);

  const ipLen = 20 + udpLen;
  const ip = Buffer.alloc(ipLen);
  ip[0] = 0x45; ip[1] = 0;
  ip.writeUInt16BE(ipLen, 2);
  ip.writeUInt16BE(Math.random() * 65535 | 0, 4);
  ip[8] = 64; ip[9] = 17; // TTL, UDP
  ipBytes(GW_IP).forEach((b, i) => { ip[12 + i] = b; });
  ipBytes(srcIp).forEach((b, i) => { ip[16 + i] = b; });
  ip.writeUInt16BE(ipChecksum(ip.slice(0, 20)), 10);
  udp.copy(ip, 20);

  const frame = buildEthernetFrame(Array.from(srcMac), GW_MAC, 0x0800, ip);
  ws.send(JSON.stringify({ type: 'receive', packetArray: Array.from(frame) }));
  console.log(`${ts()} #${connId} DNS  A? ${qname} from ${srcIp}  → ${GW_IP}`);
}

// DHCP: minimal server. Assign MAC_IP to any client, gate via GW_IP.
const DHCP_MAGIC = Buffer.from([0x63, 0x82, 0x53, 0x63]);

function parseDhcpMsgType(bootp) {
  // bootp = BOOTP payload (no UDP header)
  if (bootp.length < 240) return null;
  if (!DHCP_MAGIC.equals(bootp.slice(236, 240))) return null;
  let pos = 240;
  while (pos < bootp.length) {
    const opt = bootp[pos];
    if (opt === 255) break;
    if (opt === 0) { pos++; continue; }
    if (pos + 1 >= bootp.length) break;
    const len = bootp[pos + 1];
    if (opt === 53 && len >= 1) return bootp[pos + 2];
    pos += 2 + len;
  }
  return null;
}

function buildDhcpReply(bootp, msgType) {
  // msgType 2=OFFER, 5=ACK
  const xid = bootp.readUInt32BE(4);
  const reply = Buffer.alloc(300);
  reply[0] = 2; // BOOTREPLY
  reply[1] = 1; // htype Ethernet
  reply[2] = 6; // hlen
  reply.writeUInt32BE(xid, 4);
  // yiaddr = MAC_IP
  ipBytes(MAC_IP).forEach((b, i) => { reply[16 + i] = b; });
  // siaddr = GW_IP
  ipBytes(GW_IP).forEach((b, i) => { reply[20 + i] = b; });
  // chaddr: copy 16 bytes from bootp
  bootp.copy(reply, 28, 28, 44);
  // magic cookie
  DHCP_MAGIC.copy(reply, 236);
  // options
  let p = 240;
  function opt(code, bytes) {
    reply[p++] = code; reply[p++] = bytes.length;
    bytes.forEach(b => { reply[p++] = b; });
  }
  opt(53, [msgType]);                          // DHCP message type
  opt(54, ipBytes(GW_IP));                     // server identifier
  opt(51, [0, 1, 81, 128]);                    // lease time 86400s
  opt(1,  [255, 255, 255, 0]);                 // subnet mask
  opt(3,  ipBytes(GW_IP));                     // router
  opt(6,  ipBytes(GW_IP));                     // DNS server
  reply[p++] = 255; // end
  return reply.slice(0, p);
}

function sendDhcpReply(ws, udpSeg, srcMac, msgType, connId = '?') {
  const bootp = udpSeg.slice(8);
  const dhcpReply = buildDhcpReply(bootp, msgType);

  const udpLen = 8 + dhcpReply.length;
  const udp = Buffer.alloc(udpLen);
  udp.writeUInt16BE(67, 0); // src port
  udp.writeUInt16BE(68, 2); // dst port
  udp.writeUInt16BE(udpLen, 4);
  udp.writeUInt16BE(0, 6);
  dhcpReply.copy(udp, 8);

  const ipLen = 20 + udpLen;
  const ip = Buffer.alloc(ipLen);
  ip[0] = 0x45; ip[1] = 0;
  ip.writeUInt16BE(ipLen, 2);
  ip.writeUInt16BE(Math.random() * 65535 | 0, 4);
  ip[8] = 64; ip[9] = 17;
  ipBytes(GW_IP).forEach((b, i) => { ip[12 + i] = b; });
  // Broadcast reply so OT gets it even before it has an IP
  [255, 255, 255, 255].forEach((b, i) => { ip[16 + i] = b; });
  ip.writeUInt16BE(ipChecksum(ip.slice(0, 20)), 10);
  udp.copy(ip, 20);

  const frame = buildEthernetFrame(
    Array.from(srcMac), GW_MAC, 0x0800, ip
  );
  ws.send(JSON.stringify({ type: 'receive', packetArray: Array.from(frame) }));
  console.log(`${ts()} #${connId} DHCP ${msgType === 2 ? 'DISCOVER → OFFER' : 'REQUEST  → ACK'}  ip=${MAC_IP} gw=${GW_IP}`);
}

// ── Main packet handler ───────────────────────────────────────────────────────

function handleFrame(ws, msg, connections, connId = '?', retroBase = 'http://localhost:8000') {
  if (msg.type === 'init') {
    // handled above in connection handler
    return;
  }
  if (msg.type !== 'send' || !Array.isArray(msg.packetArray)) {
    return; // ignore non-send messages silently
  }
  const bytes = Buffer.from(msg.packetArray);
  if (bytes.length < 14) return;

  const srcMac  = bytes.slice(6, 12);
  const etherType = (bytes[12] << 8) | bytes[13];
  const payload = bytes.slice(14);

  // ARP
  if (etherType === 0x0806) {
    const op = (payload[6] << 8) | payload[7];
    if (op !== 1) return; // only handle requests
    const targetIp = ipToString(payload, 24);
    if (targetIp !== GW_IP) return; // not for us
    const senderIp = ipToString(payload, 14);
    if (CHECKPOINT < 2) return;
    const reply = buildArpReply(payload);
    try {
      ws.send(JSON.stringify({ type: 'receive', packetArray: Array.from(reply) }));
      console.log(`${ts()} #${connId} ARP  who-has ${targetIp}? tell ${senderIp}  → replied`);
      // Send an ICMP echo request from the gateway to the Mac.
      // OT may require inbound IP traffic from the gateway before it considers
      // the route live and enables outgoing TCP connections.
      setTimeout(() => sendIcmpPing(ws, payload.slice(8, 14)), 400);
    } catch (e) {
      console.error(`${ts()} #${connId} ARP  reply failed: ${e.message}`);
    }
    return;
  }

  // Non-IPv4 frames
  if (etherType !== 0x0800) {
    // Ignore emulator-level ping/pong frames (etherType 0x000c/0x000d) — these are
    // WebSocket transport probes that never touch Open Transport; not useful for diagnosis.
    if (etherType === 0x000c || etherType === 0x000d) {
      return;
    }
    // Named protocol (AppleTalk etc.) — single concise line, no hex dump
    const name = ETHER_NAMES[etherType] || `0x${etherType.toString(16)}`;
    console.log(`${ts()} #${connId} 802.3 ${name}  src=${macToString(srcMac, 0)}  len=${bytes.length}`);
    return;
  }
  const ihl  = (payload[0] & 0x0f) * 4;
  const proto = payload[9];
  const srcIp = ipToString(payload, 12);
  const dstIp = ipToString(payload, 16);

  // ICMP
  if (proto === 1) {
    const icmpType = payload[ihl];
    if (icmpType === 8 && dstIp === GW_IP) {
      sendIcmpEchoReply(ws, payload, ihl, srcIp, srcMac, connId); // logs inside
    } else if (icmpType !== 0) { // skip echo replies (we sent those)
      console.log(`${ts()} #${connId} ICMP type=${icmpType}  ${srcIp} → ${dstIp}`);
    }
    return;
  }

  // UDP — handle DHCP (port 67) and DNS (port 53)
  if (proto === 17) {
    const udp = payload.slice(ihl);
    const srcPort = (udp[0] << 8) | udp[1];
    const dstPort = (udp[2] << 8) | udp[3];

    if (dstPort === 67) {
      const bootp = udp.slice(8);
      const msgType = parseDhcpMsgType(bootp);
      if (msgType === 1) sendDhcpReply(ws, udp, srcMac, 2, connId); // OFFER — logs inside
      else if (msgType === 3) sendDhcpReply(ws, udp, srcMac, 5, connId); // ACK — logs inside
      return;
    }

    if (dstPort === 53 && dstIp === GW_IP) {
      sendDnsReply(ws, udp, srcIp, srcPort, srcMac, connId); // logs inside
      return;
    }
    // Other UDP — log briefly
    console.log(`${ts()} #${connId} UDP  ${srcIp}:${srcPort} → ${dstIp}:${dstPort}`);
    return;
  }

  // TCP
  if (proto !== 6) return;
  const tcp = payload.slice(ihl);
  const srcPort = (tcp[0] << 8) | tcp[1];
  const dstPort = (tcp[2] << 8) | tcp[3];
  const seqNum  = tcp.readUInt32BE(4);
  const tcpFlags = tcp[13];
  const dataOffset = ((tcp[12] >> 4) & 0xf) * 4;
  const tcpData = tcp.slice(dataOffset);

  const connKey = `${srcIp}:${srcPort}→${dstIp}:${dstPort}`;
  const isSyn = (tcpFlags & TCP_FLAGS.SYN) !== 0;
  const isAck = (tcpFlags & TCP_FLAGS.ACK) !== 0;
  const isFin = (tcpFlags & TCP_FLAGS.FIN) !== 0;
  const isRst = (tcpFlags & TCP_FLAGS.RST) !== 0;

  if (CHECKPOINT < 3) return; // don't log below checkpoint

  if (isSyn && !isAck) {
    // New connection
    const conn = new TcpConnection({
      ws, srcIp, srcPort, dstIp, dstPort, macSrcMac: srcMac, retroBase,
    });
    conn.clientSeq = (seqNum + 1) >>> 0;
    connections.set(connKey, conn);
    conn.send(TCP_FLAGS.SYN | TCP_FLAGS.ACK);
    conn.serverSeq = (conn.serverSeq + 1) >>> 0;
    conn.state = 'ESTABLISHED';
    console.log(`${ts()} #${connId} TCP  SYN  ${connKey}  → SYN-ACK`);
    // Port-23 telnet: send banner immediately after handshake
    if (dstPort === 23) {
      const banner = Buffer.from('Sandmill Gateway — TCP OK\r\nport=23 src=' + srcIp + ':' + srcPort + '\r\nType and press Enter to echo.\r\n\r\n');
      conn.send(TCP_FLAGS.ACK | TCP_FLAGS.PSH, banner);
    }
    return;
  }

  const conn = connections.get(connKey);
  if (!conn) return;

  if (isRst) {
    console.log(`${ts()} #${connId} TCP  RST  ${connKey}`);
    connections.delete(connKey);
    return;
  }

  if (tcpData.length > 0) {
    conn.recvBuf = Buffer.concat([conn.recvBuf, tcpData]);
    conn.clientSeq = (seqNum + tcpData.length) >>> 0;
    conn.send(TCP_FLAGS.ACK);
    console.log(`${ts()} #${connId} TCP  DATA ${connKey}  ${tcpData.length}b`);

    if (CHECKPOINT >= 4 && dstPort === 80) {
      const req = parseHttpRequest(conn.recvBuf);
      if (req) handleHttpRequest(conn, 'http').catch(e => console.error(`${ts()} #${connId} HTTP error:`, e));
    }
    if (CHECKPOINT >= 4 && dstPort === 443) {
      const req = parseHttpRequest(conn.recvBuf);
      if (req) handleHttpRequest(conn, 'https').catch(e => console.error(`${ts()} #${connId} HTTPS error:`, e));
    }
    if (dstPort === 23) {
      // Echo the data back so NiftyTelnet has something to display
      conn.send(TCP_FLAGS.ACK | TCP_FLAGS.PSH, tcpData);
    }
  } else if (!isSyn && !isFin && !isRst) {
    // Pure ACK — suppress (too noisy)
  }

  if (isFin) {
    conn.clientSeq = (conn.clientSeq + 1) >>> 0;
    conn.send(TCP_FLAGS.FIN | TCP_FLAGS.ACK);
    conn.serverSeq = (conn.serverSeq + 1) >>> 0;
    connections.delete(connKey);
    console.log(`${ts()} #${connId} TCP  FIN  ${connKey}  [closed]`);
  }
}

// ── Server setup ──────────────────────────────────────────────────────────────

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end(`Sandmill Ethernet Server — Checkpoint ${CHECKPOINT}\n`);
});

const wss = new WebSocketServer({ server });

let connIdSeq = 0;

wss.on('connection', (ws, req) => {
  const connId = ++connIdSeq;
  const zone = req.url?.match(/\/zone\/([^/]+)\/websocket/)?.[1] ?? 'unknown';
  const remote = req.socket.remoteAddress;
  console.log(`${ts()} #${connId} connected  zone=${zone}  from ${remote}`);

  // Derive retro proxy base from the WebSocket upgrade's Host header so it works
  // regardless of whether the server is reached via localhost or a named host.
  const wsHostname = (req.headers['host'] || '').split(':')[0];
  const retroBase = process.env.RETRO_BASE ||
    (wsHostname && wsHostname !== 'localhost' && wsHostname !== '127.0.0.1'
      ? `https://${wsHostname}`
      : 'http://localhost:8000');

  const connections = new Map();
  let knownMacAddress = null;

  ws.on('message', (data) => {
    let msg;
    try { msg = JSON.parse(data.toString()); } catch { return; }

    if (msg.type === 'init' && msg.macAddress) {
      knownMacAddress = msg.macAddress;
      console.log(`${ts()} #${connId} INIT mac=${msg.macAddress}`);
      return;
    }

    handleFrame(ws, msg, connections, connId, retroBase);
  });

  ws.on('close', () => {
    if (connections.size > 0) {
      console.log(`${ts()} #${connId} disconnected  (${connections.size} tcp conns cleaned up)`);
    } else {
      console.log(`${ts()} #${connId} disconnected`);
    }
    connections.clear();
  });
});

function ts() {
  return new Date().toLocaleString('sv-SE', { timeZone: 'Europe/Amsterdam' }).slice(11, 19);
}

// Known Ethernet type names for cleaner unknown-frame logging
const ETHER_NAMES = {
  0x0800: 'IPv4', 0x0806: 'ARP', 0x0835: 'RARP',
  0x809b: 'AppleTalk', 0x80f3: 'AARP', 0x8100: '802.1Q',
  0x86dd: 'IPv6', 0x88cc: 'LLDP',
};

// Extract DNS QNAME from raw DNS message bytes
function dnsExtractQname(dns) {
  if (dns.length < 13) return '?';
  let pos = 12, labels = [];
  while (pos < dns.length) {
    const len = dns[pos];
    if (len === 0) break;
    if ((len & 0xc0) === 0xc0) break; // pointer
    labels.push(dns.slice(pos + 1, pos + 1 + len).toString('ascii'));
    pos += 1 + len;
  }
  return labels.join('.') || '?';
}

server.listen(PORT, () => {
  console.log(`Sandmill Ethernet Server — Checkpoint ${CHECKPOINT}`);
  console.log(`Listening on ws://localhost:${PORT}`);
  console.log(`Virtual network: Mac=10.0.0.2, Gateway=10.0.0.1 (us)`);
  console.log('');
  console.log('Set CHECKPOINT=2 for ARP only, CHECKPOINT=3 for TCP, CHECKPOINT=4 for HTTP proxy');
  console.log('Connect Infinite Mac: ?ethernet_ws=ws://localhost:' + PORT);
});
