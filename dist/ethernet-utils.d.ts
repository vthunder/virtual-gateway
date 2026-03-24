export declare const GW_IP: readonly [10, 0, 0, 1];
export declare const MAC_IP: readonly [10, 0, 0, 2];
export declare const GW_MAC: readonly [178, 0, 0, 0, 0, 1];
export declare const BCAST_MAC: readonly [255, 255, 255, 255, 255, 255];
export declare const TCP_FLAGS: {
    readonly FIN: 1;
    readonly SYN: 2;
    readonly RST: 4;
    readonly PSH: 8;
    readonly ACK: 16;
};
export declare function ipToString(b: Uint8Array, o: number): string;
export declare function ipBytesFromString(ip: string): number[];
export declare function concatBytes(...arrays: Uint8Array[]): Uint8Array;
export declare function ipChecksum(buf: Uint8Array): number;
export declare function tcpChecksum(srcIp: number[], dstIp: number[], tcpSegment: Uint8Array): number;
export declare function udpChecksum(srcIp: number[], dstIp: number[], udpSegment: Uint8Array): number;
export declare function buildEthernetFrame(dst: ArrayLike<number>, src: ArrayLike<number>, etherType: number, payload: Uint8Array): Uint8Array;
export declare function buildArpReply(arpPayload: Uint8Array): Uint8Array;
export interface IpTcpOpts {
    srcIp: number[];
    dstIp: number[];
    srcPort: number;
    dstPort: number;
    seq: number;
    ack: number;
    flags: number;
    data: Uint8Array;
}
export declare function buildIpTcpPacket(opts: IpTcpOpts): Uint8Array;
export interface IpUdpOpts {
    srcIp: number[];
    dstIp: number[];
    srcPort: number;
    dstPort: number;
    payload: Uint8Array;
}
export declare function buildIpUdpPacket(opts: IpUdpOpts): Uint8Array;
export declare function buildIcmpPing(srcIp: number[], dstIp: number[], srcMac: Uint8Array): Uint8Array;
export declare function parseDhcpMsgType(bootp: Uint8Array): number | null;
export declare function buildDhcpReply(bootp: Uint8Array, msgType: number): Uint8Array;
export declare function buildDnsAReply(dnsQuery: Uint8Array): Uint8Array | null;
export declare function dnsExtractQname(dns: Uint8Array): string;
//# sourceMappingURL=ethernet-utils.d.ts.map