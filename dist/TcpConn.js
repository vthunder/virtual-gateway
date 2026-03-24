// TcpConn.ts — TCP connection state
export class TcpConn {
    constructor(opts) {
        this.state = 'SYN_RECEIVED';
        this.clientSeq = 0;
        this.recvBuf = new Uint8Array(0);
        this.httpHandled = false;
        this.srcIp = opts.srcIp;
        this.srcPort = opts.srcPort;
        this.dstIp = opts.dstIp;
        this.dstPort = opts.dstPort;
        this.srcMac = opts.srcMac;
        this.send = opts.send;
        this.serverSeq = ((Math.random() * 0x7fffffff) | 0) >>> 0;
    }
}
//# sourceMappingURL=TcpConn.js.map