// ethernet-utils.ts — Pure packet builder functions (no state, no Node.js APIs)
export const GW_IP = [10, 0, 0, 1];
export const MAC_IP = [10, 0, 0, 2];
export const GW_MAC = [0xb2, 0x00, 0x00, 0x00, 0x00, 0x01];
export const BCAST_MAC = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
export const TCP_FLAGS = {
    FIN: 0x01,
    SYN: 0x02,
    RST: 0x04,
    PSH: 0x08,
    ACK: 0x10,
};
// ── Utilities ──────────────────────────────────────────────────────────────────
export function ipToString(b, o) {
    return `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;
}
export function ipBytesFromString(ip) {
    return ip.split('.').map(Number);
}
export function concatBytes(...arrays) {
    const total = arrays.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrays) {
        out.set(a, off);
        off += a.length;
    }
    return out;
}
// ── Checksums ──────────────────────────────────────────────────────────────────
export function ipChecksum(buf) {
    let sum = 0;
    for (let i = 0; i < buf.length; i += 2) {
        sum += (buf[i] << 8) | (i + 1 < buf.length ? buf[i + 1] : 0);
    }
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (~sum) & 0xffff;
}
export function tcpChecksum(srcIp, dstIp, tcpSegment) {
    const pseudo = new Uint8Array(12 + tcpSegment.length);
    srcIp.forEach((b, i) => { pseudo[i] = b; });
    dstIp.forEach((b, i) => { pseudo[4 + i] = b; });
    pseudo[8] = 0;
    pseudo[9] = 6; // TCP
    pseudo[10] = (tcpSegment.length >> 8) & 0xff;
    pseudo[11] = tcpSegment.length & 0xff;
    pseudo.set(tcpSegment, 12);
    return ipChecksum(pseudo);
}
export function udpChecksum(srcIp, dstIp, udpSegment) {
    const pseudo = new Uint8Array(12 + udpSegment.length);
    srcIp.forEach((b, i) => { pseudo[i] = b; });
    dstIp.forEach((b, i) => { pseudo[4 + i] = b; });
    pseudo[8] = 0;
    pseudo[9] = 17; // UDP
    pseudo[10] = (udpSegment.length >> 8) & 0xff;
    pseudo[11] = udpSegment.length & 0xff;
    pseudo.set(udpSegment, 12);
    return ipChecksum(pseudo);
}
// ── Frame builders ──────────────────────────────────────────────────────────────
export function buildEthernetFrame(dst, src, etherType, payload) {
    const frame = new Uint8Array(14 + payload.length);
    for (let i = 0; i < 6; i++) {
        frame[i] = dst[i] ?? 0;
    }
    for (let i = 0; i < 6; i++) {
        frame[6 + i] = src[i] ?? 0;
    }
    frame[12] = (etherType >> 8) & 0xff;
    frame[13] = etherType & 0xff;
    frame.set(payload, 14);
    return frame;
}
export function buildArpReply(arpPayload) {
    // arpPayload = the ARP packet (after Ethernet header)
    const senderMac = arpPayload.slice(8, 14); // sha — Mac's MAC
    const senderIp = arpPayload.slice(14, 18); // spa — Mac's IP
    const reply = new Uint8Array(28);
    reply[0] = 0;
    reply[1] = 1; // htype: Ethernet
    reply[2] = 8;
    reply[3] = 0; // ptype: IPv4
    reply[4] = 6; // hlen
    reply[5] = 4; // plen
    reply[6] = 0;
    reply[7] = 2; // op: reply
    // sha: gateway MAC
    GW_MAC.forEach((b, i) => { reply[8 + i] = b; });
    // spa: gateway IP
    GW_IP.forEach((b, i) => { reply[14 + i] = b; });
    // tha: Mac's MAC
    reply.set(senderMac, 18);
    // tpa: Mac's IP
    reply.set(senderIp, 24);
    return buildEthernetFrame(senderMac, GW_MAC, 0x0806, reply);
}
export function buildIpTcpPacket(opts) {
    const { srcIp, dstIp, srcPort, dstPort, seq, ack, flags, data } = opts;
    const tcpLen = 20 + data.length;
    const tcp = new Uint8Array(tcpLen);
    const tcpView = new DataView(tcp.buffer);
    tcpView.setUint16(0, srcPort);
    tcpView.setUint16(2, dstPort);
    tcpView.setUint32(4, seq >>> 0);
    tcpView.setUint32(8, ack >>> 0);
    tcp[12] = 0x50; // data offset: 5 * 4 = 20 bytes
    tcp[13] = flags;
    tcpView.setUint16(14, 65535); // window
    tcpView.setUint16(16, 0); // checksum placeholder
    tcpView.setUint16(18, 0); // urgent
    tcp.set(data, 20);
    const csum = tcpChecksum(srcIp, dstIp, tcp);
    tcpView.setUint16(16, csum);
    const ipLen = 20 + tcpLen;
    const ip = new Uint8Array(ipLen);
    const ipView = new DataView(ip.buffer);
    ip[0] = 0x45; // version + IHL
    ip[1] = 0;
    ipView.setUint16(2, ipLen);
    ipView.setUint16(4, (Math.random() * 65535) | 0); // ID
    ipView.setUint16(6, 0); // flags + frag offset
    ip[8] = 64; // TTL
    ip[9] = 6; // protocol: TCP
    ipView.setUint16(10, 0); // checksum placeholder
    srcIp.forEach((b, i) => { ip[12 + i] = b; });
    dstIp.forEach((b, i) => { ip[16 + i] = b; });
    ipView.setUint16(10, ipChecksum(ip.slice(0, 20)));
    ip.set(tcp, 20);
    return ip;
}
export function buildIpUdpPacket(opts) {
    const { srcIp, dstIp, srcPort, dstPort, payload } = opts;
    const udpLen = 8 + payload.length;
    const udp = new Uint8Array(udpLen);
    const udpView = new DataView(udp.buffer);
    udpView.setUint16(0, srcPort);
    udpView.setUint16(2, dstPort);
    udpView.setUint16(4, udpLen);
    udpView.setUint16(6, 0); // checksum (optional for UDP, leave 0)
    udp.set(payload, 8);
    const ipLen = 20 + udpLen;
    const ip = new Uint8Array(ipLen);
    const ipView = new DataView(ip.buffer);
    ip[0] = 0x45;
    ip[1] = 0;
    ipView.setUint16(2, ipLen);
    ipView.setUint16(4, (Math.random() * 65535) | 0);
    ip[8] = 64; // TTL
    ip[9] = 17; // UDP
    ipView.setUint16(10, 0);
    srcIp.forEach((b, i) => { ip[12 + i] = b; });
    dstIp.forEach((b, i) => { ip[16 + i] = b; });
    ipView.setUint16(10, ipChecksum(ip.slice(0, 20)));
    ip.set(udp, 20);
    return ip;
}
// ── ICMP ──────────────────────────────────────────────────────────────────────
export function buildIcmpPing(srcIp, dstIp, srcMac) {
    const icmp = new Uint8Array(8);
    icmp[0] = 8; // type: echo request
    icmp[1] = 0; // code
    icmp[2] = 0;
    icmp[3] = 0; // checksum placeholder
    icmp[4] = 0;
    icmp[5] = 1; // identifier
    icmp[6] = 0;
    icmp[7] = 1; // sequence
    const view = new DataView(icmp.buffer);
    view.setUint16(2, ipChecksum(icmp));
    const ipLen = 20 + icmp.length;
    const ip = new Uint8Array(ipLen);
    const ipView = new DataView(ip.buffer);
    ip[0] = 0x45;
    ip[1] = 0;
    ipView.setUint16(2, ipLen);
    ipView.setUint16(4, 0x1234); // ID
    ip[8] = 64;
    ip[9] = 1; // TTL, proto ICMP
    ipView.setUint16(10, 0);
    srcIp.forEach((b, i) => { ip[12 + i] = b; });
    dstIp.forEach((b, i) => { ip[16 + i] = b; });
    ipView.setUint16(10, ipChecksum(ip.slice(0, 20)));
    ip.set(icmp, 20);
    return buildEthernetFrame(Array.from(srcMac), GW_MAC, 0x0800, ip);
}
// ── DHCP ──────────────────────────────────────────────────────────────────────
const DHCP_MAGIC = new Uint8Array([0x63, 0x82, 0x53, 0x63]);
export function parseDhcpMsgType(bootp) {
    if (bootp.length < 240)
        return null;
    for (let i = 0; i < 4; i++) {
        if (bootp[236 + i] !== DHCP_MAGIC[i])
            return null;
    }
    let pos = 240;
    while (pos < bootp.length) {
        const opt = bootp[pos];
        if (opt === 255)
            break;
        if (opt === 0) {
            pos++;
            continue;
        }
        if (pos + 1 >= bootp.length)
            break;
        const len = bootp[pos + 1];
        if (opt === 53 && len >= 1)
            return bootp[pos + 2];
        pos += 2 + len;
    }
    return null;
}
export function buildDhcpReply(bootp, msgType) {
    const view = new DataView(bootp.buffer, bootp.byteOffset);
    const xid = view.getUint32(4);
    const reply = new Uint8Array(300);
    const replyView = new DataView(reply.buffer);
    reply[0] = 2; // BOOTREPLY
    reply[1] = 1; // htype Ethernet
    reply[2] = 6; // hlen
    replyView.setUint32(4, xid);
    // yiaddr = MAC_IP
    MAC_IP.forEach((b, i) => { reply[16 + i] = b; });
    // siaddr = GW_IP
    GW_IP.forEach((b, i) => { reply[20 + i] = b; });
    // chaddr: copy 16 bytes from bootp
    reply.set(bootp.slice(28, 44), 28);
    // magic cookie
    reply.set(DHCP_MAGIC, 236);
    let p = 240;
    function opt(code, bytes) {
        reply[p++] = code;
        reply[p++] = bytes.length;
        bytes.forEach(b => { reply[p++] = b; });
    }
    opt(53, [msgType]); // DHCP message type
    opt(54, [...GW_IP]); // server identifier
    opt(51, [0, 1, 81, 128]); // lease time 86400s
    opt(1, [255, 255, 255, 0]); // subnet mask
    opt(3, [...GW_IP]); // router
    opt(6, [...GW_IP]); // DNS server
    reply[p++] = 255; // end
    return reply.slice(0, p);
}
// ── DNS ──────────────────────────────────────────────────────────────────────
export function buildDnsAReply(dnsQuery) {
    if (dnsQuery.length < 12)
        return null;
    const view = new DataView(dnsQuery.buffer, dnsQuery.byteOffset);
    const txId = view.getUint16(0);
    const qdCount = view.getUint16(4);
    if (qdCount < 1)
        return null;
    // Walk QNAME
    let pos = 12;
    while (pos < dnsQuery.length) {
        const llen = dnsQuery[pos];
        if (llen === 0) {
            pos++;
            break;
        }
        if ((llen & 0xc0) === 0xc0) {
            pos += 2;
            break;
        }
        pos += 1 + llen;
    }
    if (pos + 4 > dnsQuery.length)
        return null;
    const qtype = view.getUint16(pos);
    pos += 4; // skip QTYPE + QCLASS
    const anCount = (qtype === 1 || qtype === 255) ? 1 : 0;
    const questionBytes = dnsQuery.slice(12, pos);
    const reply = new Uint8Array(12 + questionBytes.length + (anCount ? 16 : 0));
    const rview = new DataView(reply.buffer);
    rview.setUint16(0, txId);
    rview.setUint16(2, 0x8180); // QR=1 AA=1 RD=1 RA=1 RCODE=0
    rview.setUint16(4, qdCount);
    rview.setUint16(6, anCount);
    rview.setUint16(8, 0);
    rview.setUint16(10, 0);
    reply.set(questionBytes, 12);
    if (anCount) {
        let a = 12 + questionBytes.length;
        rview.setUint16(a, 0xc00c);
        a += 2; // name ptr
        rview.setUint16(a, 1);
        a += 2; // TYPE A
        rview.setUint16(a, 1);
        a += 2; // CLASS IN
        rview.setUint32(a, 300);
        a += 4; // TTL 300s
        rview.setUint16(a, 4);
        a += 2; // RDLENGTH
        GW_IP.forEach((b, i) => { reply[a + i] = b; });
    }
    return reply;
}
export function dnsExtractQname(dns) {
    if (dns.length < 13)
        return '?';
    let pos = 12;
    const labels = [];
    while (pos < dns.length) {
        const len = dns[pos];
        if (len === 0)
            break;
        if ((len & 0xc0) === 0xc0)
            break;
        labels.push(new TextDecoder('ascii').decode(dns.slice(pos + 1, pos + 1 + len)));
        pos += 1 + len;
    }
    return labels.join('.') || '?';
}
//# sourceMappingURL=ethernet-utils.js.map