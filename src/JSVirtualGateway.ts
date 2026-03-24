// JSVirtualGateway.ts — Protocol engine (ARP, DHCP, DNS, TCP, HTTP, /nav/)
// No Node.js APIs — runs in browser / Cloudflare Worker context.

import { TcpConn } from './TcpConn.js';
import {
  GW_IP, MAC_IP, GW_MAC, BCAST_MAC, TCP_FLAGS,
  ipToString, ipBytesFromString,
  buildEthernetFrame, buildArpReply,
  buildIpTcpPacket, buildIpUdpPacket,
  buildIcmpPing,
  parseDhcpMsgType, buildDhcpReply,
  buildDnsAReply, dnsExtractQname,
  ipChecksum,
} from './ethernet-utils.js';

const GW_IP_STR = GW_IP.join('.');
const MAC_IP_STR = MAC_IP.join('.');

const GATEWAY_PAGE = new TextEncoder().encode([
  '<html><head><title>Sandmill Gateway</title></head><body>',
  '<h2>Sandmill Gateway</h2>',
  '<p>You are connected to the Sandmill ethernet gateway.</p>',
  '<p>Try: <a href="http://sandmill.org/">http://sandmill.org/</a></p>',
  '</body></html>',
].join(''));

const CHUNK_SIZE = 1460; // TCP MSS

export class JSVirtualGateway {
  #send: (packet: Uint8Array) => void;
  #proxyBaseUrl: string;
  #tcpConns: Map<string, TcpConn> = new Map();
  #macAddress: string | undefined;

  constructor(proxyBaseUrl: string, send: (p: Uint8Array) => void) {
    this.#proxyBaseUrl = proxyBaseUrl.replace(/\/$/, '');
    this.#send = send;
  }

  setMacAddress(mac: string) {
    this.#macAddress = mac;
  }

  handleFrame(frame: Uint8Array): void {
    if (frame.length < 14) return;
    const etherType = (frame[12] << 8) | frame[13];
    const payload = frame.slice(14);

    if (etherType === 0x0806) {
      this.#handleArp(frame, payload);
    } else if (etherType === 0x0800) {
      this.#handleIp(frame, payload);
    }
    // All other etherTypes dropped silently
  }

  // ── ARP ─────────────────────────────────────────────────────────────────────

  #handleArp(frame: Uint8Array, payload: Uint8Array): void {
    if (payload.length < 28) return;
    const op = (payload[6] << 8) | payload[7];
    if (op !== 1) return; // only handle requests
    const targetIp = ipToString(payload, 24);
    if (targetIp !== GW_IP_STR) return; // not for us

    const reply = buildArpReply(payload);
    this.#sendFrame(reply);
    console.log(`[gw] ARP reply sent → ${ipToString(payload, 14)}`);

    // Send ICMP ping 400ms later to prime Open Transport's route table
    const srcMac = frame.slice(6, 12);
    setTimeout(() => {
      const ping = buildIcmpPing([...GW_IP], [...MAC_IP], srcMac);
      this.#sendFrame(ping);
      console.log(`[gw] ICMP ping sent → ${MAC_IP_STR}`);
    }, 400);
  }

  // ── IP demux ─────────────────────────────────────────────────────────────────

  #handleIp(frame: Uint8Array, ip: Uint8Array): void {
    if (ip.length < 20) return;
    const ihl = (ip[0] & 0x0f) * 4;
    const proto = ip[9];
    const srcIp = ipToString(ip, 12);
    const dstIp = ipToString(ip, 16);
    const srcMac = frame.slice(6, 12);

    if (proto === 1) {
      // ICMP
      const icmpType = ip[ihl];
      if (icmpType === 8 && dstIp === GW_IP_STR) {
        this.#sendIcmpEchoReply(ip, ihl, srcIp, srcMac);
      }
    } else if (proto === 17) {
      // UDP
      const udp = ip.slice(ihl);
      if (udp.length < 8) return;
      const srcPort = (udp[0] << 8) | udp[1];
      const dstPort = (udp[2] << 8) | udp[3];
      this.#handleUdp(udp, srcPort, dstPort, srcIp, dstIp, srcMac);
    } else if (proto === 6) {
      // TCP
      const tcp = ip.slice(ihl);
      this.#handleTcp(tcp, srcIp, dstIp, srcMac);
    }
  }

  // ── ICMP echo reply ───────────────────────────────────────────────────────────

  #sendIcmpEchoReply(ipPacket: Uint8Array, ihl: number, srcIp: string, srcMac: Uint8Array): void {
    const icmpData = ipPacket.slice(ihl);
    const reply = new Uint8Array(icmpData.length);
    reply.set(icmpData);
    reply[0] = 0; // echo reply
    reply[1] = 0;
    reply[2] = 0; reply[3] = 0;
    const view = new DataView(reply.buffer);
    view.setUint16(2, ipChecksum(reply));

    const ipLen = 20 + reply.length;
    const ip = new Uint8Array(ipLen);
    const ipView = new DataView(ip.buffer);
    ip[0] = 0x45;
    ipView.setUint16(2, ipLen);
    const origView = new DataView(ipPacket.buffer, ipPacket.byteOffset);
    ipView.setUint16(4, origView.getUint16(4)); // same IP ID
    ip[8] = 64; ip[9] = 1; // TTL, ICMP
    [...GW_IP].forEach((b, i) => { ip[12 + i] = b; });
    ipBytesFromString(srcIp).forEach((b, i) => { ip[16 + i] = b; });
    ipView.setUint16(10, ipChecksum(ip.slice(0, 20)));
    ip.set(reply, 20);

    this.#sendFrame(buildEthernetFrame(Array.from(srcMac), GW_MAC, 0x0800, ip));
  }

  // ── UDP dispatcher ────────────────────────────────────────────────────────────

  #handleUdp(
    udp: Uint8Array,
    srcPort: number,
    dstPort: number,
    srcIp: string,
    dstIp: string,
    srcMac: Uint8Array,
  ): void {
    if (dstPort === 67) {
      const bootp = udp.slice(8);
      const msgType = parseDhcpMsgType(bootp);
      if (msgType === 1) this.#sendDhcpReply(bootp, srcMac, 2);   // DISCOVER → OFFER
      else if (msgType === 3) this.#sendDhcpReply(bootp, srcMac, 5); // REQUEST → ACK
    } else if (dstPort === 53 && dstIp === GW_IP_STR) {
      this.#handleDns(udp.slice(8), srcIp, srcPort, srcMac);
    }
  }

  // ── DHCP ──────────────────────────────────────────────────────────────────────

  #sendDhcpReply(bootp: Uint8Array, srcMac: Uint8Array, msgType: number): void {
    const dhcpReply = buildDhcpReply(bootp, msgType);

    const ipPacket = buildIpUdpPacket({
      srcIp: [...GW_IP],
      dstIp: [255, 255, 255, 255], // broadcast
      srcPort: 67,
      dstPort: 68,
      payload: dhcpReply,
    });

    this.#sendFrame(buildEthernetFrame(Array.from(srcMac), GW_MAC, 0x0800, ipPacket));
    const label = msgType === 2 ? 'DISCOVER → OFFER' : 'REQUEST  → ACK';
    console.log(`[gw] DHCP ${label}  ip=${MAC_IP_STR} gw=${GW_IP_STR}`);
  }

  // ── DNS ──────────────────────────────────────────────────────────────────────

  #handleDns(dnsPayload: Uint8Array, srcIp: string, srcPort: number, srcMac: Uint8Array): void {
    const qname = dnsExtractQname(dnsPayload);
    const dnsReply = buildDnsAReply(dnsPayload);
    if (!dnsReply) return;

    const ipPacket = buildIpUdpPacket({
      srcIp: [...GW_IP],
      dstIp: ipBytesFromString(srcIp),
      srcPort: 53,
      dstPort: srcPort,
      payload: dnsReply,
    });

    this.#sendFrame(buildEthernetFrame(Array.from(srcMac), GW_MAC, 0x0800, ipPacket));
    console.log(`[gw] DNS  A? ${qname} → ${GW_IP_STR}`);
  }

  // ── TCP state machine ─────────────────────────────────────────────────────────

  #handleTcp(tcp: Uint8Array, srcIp: string, dstIp: string, srcMac: Uint8Array): void {
    if (tcp.length < 20) return;
    const tcpView = new DataView(tcp.buffer, tcp.byteOffset);
    const srcPort = tcpView.getUint16(0);
    const dstPort = tcpView.getUint16(2);
    const seqNum  = tcpView.getUint32(4);
    const tcpFlags = tcp[13];
    const dataOffset = ((tcp[12] >> 4) & 0xf) * 4;
    const tcpData = tcp.slice(dataOffset);

    const connKey = `${srcIp}:${srcPort}→${dstIp}:${dstPort}`;
    const isSyn = (tcpFlags & TCP_FLAGS.SYN) !== 0;
    const isAck = (tcpFlags & TCP_FLAGS.ACK) !== 0;
    const isFin = (tcpFlags & TCP_FLAGS.FIN) !== 0;
    const isRst = (tcpFlags & TCP_FLAGS.RST) !== 0;

    const makeSendFn = (conn: TcpConn) => (flags: number, data: Uint8Array = new Uint8Array(0)) => {
      const ipPacket = buildIpTcpPacket({
        srcIp: [...GW_IP],
        dstIp: ipBytesFromString(conn.srcIp),
        srcPort: conn.dstPort,
        dstPort: conn.srcPort,
        seq: conn.serverSeq,
        ack: conn.clientSeq,
        flags,
        data,
      });
      this.#sendFrame(buildEthernetFrame(Array.from(conn.srcMac), GW_MAC, 0x0800, ipPacket));
      if (data.length > 0) conn.serverSeq = (conn.serverSeq + data.length) >>> 0;
    };

    if (isSyn && !isAck) {
      // New connection
      const conn = new TcpConn({
        srcIp, srcPort, dstIp, dstPort,
        srcMac: srcMac.slice(0),
        send: () => {}, // placeholder, set below
      });
      conn.send = makeSendFn(conn);
      conn.clientSeq = (seqNum + 1) >>> 0;
      this.#tcpConns.set(connKey, conn);

      conn.send(TCP_FLAGS.SYN | TCP_FLAGS.ACK);
      conn.serverSeq = (conn.serverSeq + 1) >>> 0;
      conn.state = 'ESTABLISHED';
      console.log(`[gw] TCP  SYN  ${connKey} → SYN-ACK`);

      // Port 23 telnet banner
      if (dstPort === 23) {
        const banner = new TextEncoder().encode(
          `Sandmill Gateway — TCP OK\r\nport=23 src=${srcIp}:${srcPort}\r\nType and press Enter to echo.\r\n\r\n`
        );
        conn.send(TCP_FLAGS.ACK | TCP_FLAGS.PSH, banner);
      }
      return;
    }

    const conn = this.#tcpConns.get(connKey);
    if (!conn) return;

    if (isRst) {
      this.#tcpConns.delete(connKey);
      return;
    }

    if (tcpData.length > 0) {
      // Append to recv buffer
      const newBuf = new Uint8Array(conn.recvBuf.length + tcpData.length);
      newBuf.set(conn.recvBuf);
      newBuf.set(tcpData, conn.recvBuf.length);
      conn.recvBuf = newBuf;
      conn.clientSeq = (seqNum + tcpData.length) >>> 0;
      conn.send(TCP_FLAGS.ACK);
      console.log(`[gw] TCP  DATA ${connKey}  ${tcpData.length}b`);

      if (dstPort === 80 || dstPort === 443) {
        const req = parseHttpRequest(conn.recvBuf);
        if (req) {
          this.#handleHttp(conn, dstPort === 443 ? 'https' : 'http')
            .catch(e => console.error('[gw] HTTP error:', e));
        }
      }
      if (dstPort === 23) {
        // Echo back
        conn.send(TCP_FLAGS.ACK | TCP_FLAGS.PSH, tcpData);
      }
    }

    if (isFin) {
      conn.clientSeq = (conn.clientSeq + 1) >>> 0;
      conn.send(TCP_FLAGS.FIN | TCP_FLAGS.ACK);
      conn.serverSeq = (conn.serverSeq + 1) >>> 0;
      this.#tcpConns.delete(connKey);
      console.log(`[gw] TCP  FIN  ${connKey} [closed]`);
    }
  }

  // ── HTTP handler ──────────────────────────────────────────────────────────────

  async #handleHttp(conn: TcpConn, scheme: 'http' | 'https'): Promise<void> {
    if (conn.httpHandled) return;
    conn.httpHandled = true;

    const req = parseHttpRequest(conn.recvBuf);
    if (!req) {
      conn.send(TCP_FLAGS.RST);
      return;
    }

    const host = req.headers['host'] ?? conn.dstIp;
    let url = (req.path.startsWith('http://') || req.path.startsWith('https://'))
      ? req.path
      : `${scheme}://${host}${req.path}`;

    // Navigation intercept: GET http://10.0.0.1/nav/<path>
    if (conn.dstIp === GW_IP_STR && req.path.startsWith('/nav/')) {
      const navPath = '/' + req.path.slice(5); // /nav/blog → /blog
      console.log(`[gw] HTTP nav → ${navPath}`);
      this.#sendHttpResponse(conn, 200, 'OK', 'text/html',
        new TextEncoder().encode(`<html><body>Navigating to ${navPath}...</body></html>`)
      );
      // Notify parent page
      if (typeof window !== 'undefined') {
        window.parent.postMessage({ type: 'emulator_nav', path: navPath }, '*');
      }
      return;
    }

    // Gateway self-request
    const hostHeader = (req.headers['host'] ?? '').split(':')[0];
    const isGatewayRequest = !req.headers['host'] || hostHeader === GW_IP_STR;
    if (isGatewayRequest) {
      console.log(`[gw] HTTP gateway self-page`);
      this.#sendHttpResponse(conn, 200, 'OK', 'text/html', GATEWAY_PAGE);
      return;
    }

    // Real hostname — proxy via fetch()
    let statusCode = 502;
    let statusText = 'Bad Gateway';
    let contentType = 'text/html';
    let responseBody: Uint8Array;

    try {
      const result = await this.#fetchViaProxy(url);
      statusCode = result.status;
      statusText = HTTP_STATUS[statusCode] ?? 'Unknown';
      contentType = result.contentType;
      responseBody = result.body;
      console.log(`[gw] HTTP ${req.method} ${url} → ${statusCode} ${statusText} ${responseBody.length}b ${contentType}`);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error(`[gw] HTTP fetch error: ${msg}`);
      responseBody = new TextEncoder().encode(`<html><body>Proxy error: ${msg}</body></html>`);
    }

    this.#sendHttpResponse(conn, statusCode, statusText, contentType, responseBody!);
  }

  #sendHttpResponse(
    conn: TcpConn,
    status: number,
    statusText: string,
    contentType: string,
    body: Uint8Array,
  ): void {
    const headerStr = [
      `HTTP/1.0 ${status} ${statusText}`,
      `Content-Length: ${body.length}`,
      `Content-Type: ${contentType}`,
      `Connection: close`,
      '', '',
    ].join('\r\n');
    const header = new TextEncoder().encode(headerStr);
    const full = new Uint8Array(header.length + body.length);
    full.set(header);
    full.set(body, header.length);

    for (let offset = 0; offset < full.length; offset += CHUNK_SIZE) {
      const chunk = full.slice(offset, offset + CHUNK_SIZE);
      conn.send(TCP_FLAGS.ACK | TCP_FLAGS.PSH, chunk);
    }
    conn.send(TCP_FLAGS.FIN | TCP_FLAGS.ACK);
    conn.state = 'FIN_SENT';
  }

  // ── Proxy fetch ───────────────────────────────────────────────────────────────

  async #fetchViaProxy(url: string): Promise<{status: number; contentType: string; body: Uint8Array}> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
      const proxyUrl = `${this.#proxyBaseUrl}?url=${encodeURIComponent(url)}`;
      const resp = await fetch(proxyUrl, {
        method: 'GET',
        headers: { 'Accept': 'text/html, */*' },
        signal: controller.signal,
      });
      const buf = await resp.arrayBuffer();
      const rawCT = resp.headers.get('content-type') ?? 'application/octet-stream';
      const contentType = rawCT.split(';')[0].trim();
      return { status: resp.status, contentType, body: new Uint8Array(buf) };
    } finally {
      clearTimeout(timer);
    }
  }

  // ── Internal send ─────────────────────────────────────────────────────────────

  #sendFrame(frame: Uint8Array): void {
    this.#send(frame);
  }
}

// ── HTTP request parser ───────────────────────────────────────────────────────

interface HttpRequest {
  method: string;
  path: string;
  version: string;
  headers: Record<string, string>;
  body: Uint8Array;
}

function parseHttpRequest(buf: Uint8Array): HttpRequest | null {
  const str = new TextDecoder('latin1').decode(buf);
  const headerEnd = str.indexOf('\r\n\r\n');
  if (headerEnd === -1) return null;
  const headerSection = str.slice(0, headerEnd);
  const lines = headerSection.split('\r\n');
  const [method, path, version] = lines[0].split(' ');
  const headers: Record<string, string> = {};
  for (let i = 1; i < lines.length; i++) {
    const colon = lines[i].indexOf(':');
    if (colon !== -1) {
      headers[lines[i].slice(0, colon).toLowerCase()] = lines[i].slice(colon + 1).trim();
    }
  }
  const bodyStart = headerEnd + 4;
  const contentLength = parseInt(headers['content-length'] ?? '0', 10);
  if (buf.length < bodyStart + contentLength) return null;
  return { method, path, version, headers, body: buf.slice(bodyStart, bodyStart + contentLength) };
}

// Common HTTP status codes
const HTTP_STATUS: Record<number, string> = {
  200: 'OK', 201: 'Created', 204: 'No Content',
  301: 'Moved Permanently', 302: 'Found', 304: 'Not Modified',
  400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden',
  404: 'Not Found', 500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable',
};
