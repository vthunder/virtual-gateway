// JSVirtualGateway.ts — Protocol engine (ARP, DHCP, DNS, TCP, HTTP, /nav/)
// No Node.js APIs — runs in browser / Cloudflare Worker context.
var __classPrivateFieldSet = (this && this.__classPrivateFieldSet) || function (receiver, state, value, kind, f) {
    if (kind === "m") throw new TypeError("Private method is not writable");
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
    return (kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value)), value;
};
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var _JSVirtualGateway_instances, _JSVirtualGateway_send, _JSVirtualGateway_proxyBaseUrl, _JSVirtualGateway_tcpConns, _JSVirtualGateway_macAddress, _JSVirtualGateway_handleArp, _JSVirtualGateway_handleIp, _JSVirtualGateway_sendIcmpEchoReply, _JSVirtualGateway_handleUdp, _JSVirtualGateway_sendDhcpReply, _JSVirtualGateway_handleDns, _JSVirtualGateway_handleTcp, _JSVirtualGateway_handleHttp, _JSVirtualGateway_sendHttpResponse, _JSVirtualGateway_fetchViaProxy, _JSVirtualGateway_sendFrame;
import { TcpConn } from './TcpConn.js';
import { GW_IP, MAC_IP, GW_MAC, TCP_FLAGS, ipToString, ipBytesFromString, buildEthernetFrame, buildArpReply, buildIpTcpPacket, buildIpUdpPacket, buildIcmpPing, parseDhcpMsgType, buildDhcpReply, buildDnsAReply, dnsExtractQname, ipChecksum, } from './ethernet-utils.js';
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
    constructor(proxyBaseUrl, send) {
        _JSVirtualGateway_instances.add(this);
        _JSVirtualGateway_send.set(this, void 0);
        _JSVirtualGateway_proxyBaseUrl.set(this, void 0);
        _JSVirtualGateway_tcpConns.set(this, new Map());
        _JSVirtualGateway_macAddress.set(this, void 0);
        __classPrivateFieldSet(this, _JSVirtualGateway_proxyBaseUrl, proxyBaseUrl.replace(/\/$/, ''), "f");
        __classPrivateFieldSet(this, _JSVirtualGateway_send, send, "f");
    }
    setMacAddress(mac) {
        __classPrivateFieldSet(this, _JSVirtualGateway_macAddress, mac, "f");
    }
    handleFrame(frame) {
        if (frame.length < 14)
            return;
        const etherType = (frame[12] << 8) | frame[13];
        const payload = frame.slice(14);
        if (etherType === 0x0806) {
            __classPrivateFieldGet(this, _JSVirtualGateway_instances, "m", _JSVirtualGateway_handleArp).call(this, frame, payload);
        }
        else if (etherType === 0x0800) {
            __classPrivateFieldGet(this, _JSVirtualGateway_instances, "m", _JSVirtualGateway_handleIp).call(this, frame, payload);
        }
        // All other etherTypes dropped silently
    }
}
_JSVirtualGateway_send = new WeakMap(), _JSVirtualGateway_proxyBaseUrl = new WeakMap(), _JSVirtualGateway_tcpConns = new WeakMap(), _JSVirtualGateway_macAddress = new WeakMap(), _JSVirtualGateway_instances = new WeakSet(), _JSVirtualGateway_handleArp = function _JSVirtualGateway_handleArp(frame, payload) {
    if (payload.length < 28)
        return;
    const op = (payload[6] << 8) | payload[7];
    if (op !== 1)
        return; // only handle requests
    const targetIp = ipToString(payload, 24);
    if (targetIp !== GW_IP_STR)
        return; // not for us
    const reply = buildArpReply(payload);
    __classPrivateFieldGet(this, _JSVirtualGateway_instances, "m", _JSVirtualGateway_sendFrame).call(this, reply);
    console.log(`[gw] ARP reply sent → ${ipToString(payload, 14)}`);
    // Send ICMP ping 400ms later to prime Open Transport's route table
    const srcMac = frame.slice(6, 12);
    setTimeout(() => {
        const ping = buildIcmpPing([...GW_IP], [...MAC_IP], srcMac);
        __classPrivateFieldGet(this, _JSVirtualGateway_instances, "m", _JSVirtualGateway_sendFrame).call(this, ping);
        console.log(`[gw] ICMP ping sent → ${MAC_IP_STR}`);
    }, 400);
}, _JSVirtualGateway_handleIp = function _JSVirtualGateway_handleIp(frame, ip) {
    if (ip.length < 20)
        return;
    const ihl = (ip[0] & 0x0f) * 4;
    const proto = ip[9];
    const srcIp = ipToString(ip, 12);
    const dstIp = ipToString(ip, 16);
    const srcMac = frame.slice(6, 12);
    if (proto === 1) {
        // ICMP
        const icmpType = ip[ihl];
        if (icmpType === 8 && dstIp === GW_IP_STR) {
            __classPrivateFieldGet(this, _JSVirtualGateway_instances, "m", _JSVirtualGateway_sendIcmpEchoReply).call(this, ip, ihl, srcIp, srcMac);
        }
    }
    else if (proto === 17) {
        // UDP
        const udp = ip.slice(ihl);
        if (udp.length < 8)
            return;
        const srcPort = (udp[0] << 8) | udp[1];
        const dstPort = (udp[2] << 8) | udp[3];
        __classPrivateFieldGet(this, _JSVirtualGateway_instances, "m", _JSVirtualGateway_handleUdp).call(this, udp, srcPort, dstPort, srcIp, dstIp, srcMac);
    }
    else if (proto === 6) {
        // TCP
        const tcp = ip.slice(ihl);
        __classPrivateFieldGet(this, _JSVirtualGateway_instances, "m", _JSVirtualGateway_handleTcp).call(this, tcp, srcIp, dstIp, srcMac);
    }
}, _JSVirtualGateway_sendIcmpEchoReply = function _JSVirtualGateway_sendIcmpEchoReply(ipPacket, ihl, srcIp, srcMac) {
    const icmpData = ipPacket.slice(ihl);
    const reply = new Uint8Array(icmpData.length);
    reply.set(icmpData);
    reply[0] = 0; // echo reply
    reply[1] = 0;
    reply[2] = 0;
    reply[3] = 0;
    const view = new DataView(reply.buffer);
    view.setUint16(2, ipChecksum(reply));
    const ipLen = 20 + reply.length;
    const ip = new Uint8Array(ipLen);
    const ipView = new DataView(ip.buffer);
    ip[0] = 0x45;
    ipView.setUint16(2, ipLen);
    const origView = new DataView(ipPacket.buffer, ipPacket.byteOffset);
    ipView.setUint16(4, origView.getUint16(4)); // same IP ID
    ip[8] = 64;
    ip[9] = 1; // TTL, ICMP
    [...GW_IP].forEach((b, i) => { ip[12 + i] = b; });
    ipBytesFromString(srcIp).forEach((b, i) => { ip[16 + i] = b; });
    ipView.setUint16(10, ipChecksum(ip.slice(0, 20)));
    ip.set(reply, 20);
    __classPrivateFieldGet(this, _JSVirtualGateway_instances, "m", _JSVirtualGateway_sendFrame).call(this, buildEthernetFrame(Array.from(srcMac), GW_MAC, 0x0800, ip));
}, _JSVirtualGateway_handleUdp = function _JSVirtualGateway_handleUdp(udp, srcPort, dstPort, srcIp, dstIp, srcMac) {
    if (dstPort === 67) {
        const bootp = udp.slice(8);
        const msgType = parseDhcpMsgType(bootp);
        if (msgType === 1)
            __classPrivateFieldGet(this, _JSVirtualGateway_instances, "m", _JSVirtualGateway_sendDhcpReply).call(this, bootp, srcMac, 2); // DISCOVER → OFFER
        else if (msgType === 3)
            __classPrivateFieldGet(this, _JSVirtualGateway_instances, "m", _JSVirtualGateway_sendDhcpReply).call(this, bootp, srcMac, 5); // REQUEST → ACK
    }
    else if (dstPort === 53 && dstIp === GW_IP_STR) {
        __classPrivateFieldGet(this, _JSVirtualGateway_instances, "m", _JSVirtualGateway_handleDns).call(this, udp.slice(8), srcIp, srcPort, srcMac);
    }
}, _JSVirtualGateway_sendDhcpReply = function _JSVirtualGateway_sendDhcpReply(bootp, srcMac, msgType) {
    const dhcpReply = buildDhcpReply(bootp, msgType);
    const ipPacket = buildIpUdpPacket({
        srcIp: [...GW_IP],
        dstIp: [255, 255, 255, 255], // broadcast
        srcPort: 67,
        dstPort: 68,
        payload: dhcpReply,
    });
    __classPrivateFieldGet(this, _JSVirtualGateway_instances, "m", _JSVirtualGateway_sendFrame).call(this, buildEthernetFrame(Array.from(srcMac), GW_MAC, 0x0800, ipPacket));
    const label = msgType === 2 ? 'DISCOVER → OFFER' : 'REQUEST  → ACK';
    console.log(`[gw] DHCP ${label}  ip=${MAC_IP_STR} gw=${GW_IP_STR}`);
}, _JSVirtualGateway_handleDns = function _JSVirtualGateway_handleDns(dnsPayload, srcIp, srcPort, srcMac) {
    const qname = dnsExtractQname(dnsPayload);
    const dnsReply = buildDnsAReply(dnsPayload);
    if (!dnsReply)
        return;
    const ipPacket = buildIpUdpPacket({
        srcIp: [...GW_IP],
        dstIp: ipBytesFromString(srcIp),
        srcPort: 53,
        dstPort: srcPort,
        payload: dnsReply,
    });
    __classPrivateFieldGet(this, _JSVirtualGateway_instances, "m", _JSVirtualGateway_sendFrame).call(this, buildEthernetFrame(Array.from(srcMac), GW_MAC, 0x0800, ipPacket));
    console.log(`[gw] DNS  A? ${qname} → ${GW_IP_STR}`);
}, _JSVirtualGateway_handleTcp = function _JSVirtualGateway_handleTcp(tcp, srcIp, dstIp, srcMac) {
    if (tcp.length < 20)
        return;
    const tcpView = new DataView(tcp.buffer, tcp.byteOffset);
    const srcPort = tcpView.getUint16(0);
    const dstPort = tcpView.getUint16(2);
    const seqNum = tcpView.getUint32(4);
    const tcpFlags = tcp[13];
    const dataOffset = ((tcp[12] >> 4) & 0xf) * 4;
    const tcpData = tcp.slice(dataOffset);
    const connKey = `${srcIp}:${srcPort}→${dstIp}:${dstPort}`;
    const isSyn = (tcpFlags & TCP_FLAGS.SYN) !== 0;
    const isAck = (tcpFlags & TCP_FLAGS.ACK) !== 0;
    const isFin = (tcpFlags & TCP_FLAGS.FIN) !== 0;
    const isRst = (tcpFlags & TCP_FLAGS.RST) !== 0;
    const makeSendFn = (conn) => (flags, data = new Uint8Array(0)) => {
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
        __classPrivateFieldGet(this, _JSVirtualGateway_instances, "m", _JSVirtualGateway_sendFrame).call(this, buildEthernetFrame(Array.from(conn.srcMac), GW_MAC, 0x0800, ipPacket));
        if (data.length > 0)
            conn.serverSeq = (conn.serverSeq + data.length) >>> 0;
    };
    if (isSyn && !isAck) {
        // New connection
        const conn = new TcpConn({
            srcIp, srcPort, dstIp, dstPort,
            srcMac: srcMac.slice(0),
            send: () => { }, // placeholder, set below
        });
        conn.send = makeSendFn(conn);
        conn.clientSeq = (seqNum + 1) >>> 0;
        __classPrivateFieldGet(this, _JSVirtualGateway_tcpConns, "f").set(connKey, conn);
        conn.send(TCP_FLAGS.SYN | TCP_FLAGS.ACK);
        conn.serverSeq = (conn.serverSeq + 1) >>> 0;
        conn.state = 'ESTABLISHED';
        console.log(`[gw] TCP  SYN  ${connKey} → SYN-ACK`);
        // Port 23 telnet banner
        if (dstPort === 23) {
            const banner = new TextEncoder().encode(`Sandmill Gateway — TCP OK\r\nport=23 src=${srcIp}:${srcPort}\r\nType and press Enter to echo.\r\n\r\n`);
            conn.send(TCP_FLAGS.ACK | TCP_FLAGS.PSH, banner);
        }
        return;
    }
    const conn = __classPrivateFieldGet(this, _JSVirtualGateway_tcpConns, "f").get(connKey);
    if (!conn)
        return;
    if (isRst) {
        __classPrivateFieldGet(this, _JSVirtualGateway_tcpConns, "f").delete(connKey);
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
                __classPrivateFieldGet(this, _JSVirtualGateway_instances, "m", _JSVirtualGateway_handleHttp).call(this, conn, dstPort === 443 ? 'https' : 'http')
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
        __classPrivateFieldGet(this, _JSVirtualGateway_tcpConns, "f").delete(connKey);
        console.log(`[gw] TCP  FIN  ${connKey} [closed]`);
    }
}, _JSVirtualGateway_handleHttp = 
// ── HTTP handler ──────────────────────────────────────────────────────────────
async function _JSVirtualGateway_handleHttp(conn, scheme) {
    if (conn.httpHandled)
        return;
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
        __classPrivateFieldGet(this, _JSVirtualGateway_instances, "m", _JSVirtualGateway_sendHttpResponse).call(this, conn, 200, 'OK', 'text/html', new TextEncoder().encode(`<html><body>Navigating to ${navPath}...</body></html>`));
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
        __classPrivateFieldGet(this, _JSVirtualGateway_instances, "m", _JSVirtualGateway_sendHttpResponse).call(this, conn, 200, 'OK', 'text/html', GATEWAY_PAGE);
        return;
    }
    // Real hostname — proxy via fetch()
    let statusCode = 502;
    let statusText = 'Bad Gateway';
    let contentType = 'text/html';
    let responseBody;
    try {
        const result = await __classPrivateFieldGet(this, _JSVirtualGateway_instances, "m", _JSVirtualGateway_fetchViaProxy).call(this, url);
        statusCode = result.status;
        statusText = HTTP_STATUS[statusCode] ?? 'Unknown';
        contentType = result.contentType;
        responseBody = result.body;
        console.log(`[gw] HTTP ${req.method} ${url} → ${statusCode} ${statusText} ${responseBody.length}b ${contentType}`);
    }
    catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        console.error(`[gw] HTTP fetch error: ${msg}`);
        responseBody = new TextEncoder().encode(`<html><body>Proxy error: ${msg}</body></html>`);
    }
    __classPrivateFieldGet(this, _JSVirtualGateway_instances, "m", _JSVirtualGateway_sendHttpResponse).call(this, conn, statusCode, statusText, contentType, responseBody);
}, _JSVirtualGateway_sendHttpResponse = function _JSVirtualGateway_sendHttpResponse(conn, status, statusText, contentType, body) {
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
}, _JSVirtualGateway_fetchViaProxy = 
// ── Proxy fetch ───────────────────────────────────────────────────────────────
async function _JSVirtualGateway_fetchViaProxy(url) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
        const proxyUrl = `${__classPrivateFieldGet(this, _JSVirtualGateway_proxyBaseUrl, "f")}?url=${encodeURIComponent(url)}`;
        const resp = await fetch(proxyUrl, {
            method: 'GET',
            headers: { 'Accept': 'text/html, */*' },
            signal: controller.signal,
        });
        const buf = await resp.arrayBuffer();
        const rawCT = resp.headers.get('content-type') ?? 'application/octet-stream';
        const contentType = rawCT.split(';')[0].trim();
        return { status: resp.status, contentType, body: new Uint8Array(buf) };
    }
    finally {
        clearTimeout(timer);
    }
}, _JSVirtualGateway_sendFrame = function _JSVirtualGateway_sendFrame(frame) {
    __classPrivateFieldGet(this, _JSVirtualGateway_send, "f").call(this, frame);
};
function parseHttpRequest(buf) {
    const str = new TextDecoder('latin1').decode(buf);
    const headerEnd = str.indexOf('\r\n\r\n');
    if (headerEnd === -1)
        return null;
    const headerSection = str.slice(0, headerEnd);
    const lines = headerSection.split('\r\n');
    const [method, path, version] = lines[0].split(' ');
    const headers = {};
    for (let i = 1; i < lines.length; i++) {
        const colon = lines[i].indexOf(':');
        if (colon !== -1) {
            headers[lines[i].slice(0, colon).toLowerCase()] = lines[i].slice(colon + 1).trim();
        }
    }
    const bodyStart = headerEnd + 4;
    const contentLength = parseInt(headers['content-length'] ?? '0', 10);
    if (buf.length < bodyStart + contentLength)
        return null;
    return { method, path, version, headers, body: buf.slice(bodyStart, bodyStart + contentLength) };
}
// Common HTTP status codes
const HTTP_STATUS = {
    200: 'OK', 201: 'Created', 204: 'No Content',
    301: 'Moved Permanently', 302: 'Found', 304: 'Not Modified',
    400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden',
    404: 'Not Found', 500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable',
};
//# sourceMappingURL=JSVirtualGateway.js.map