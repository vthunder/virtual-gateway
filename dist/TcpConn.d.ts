export type TcpConnState = 'SYN_RECEIVED' | 'ESTABLISHED' | 'FIN_SENT' | 'CLOSED';
export declare class TcpConn {
    state: TcpConnState;
    serverSeq: number;
    clientSeq: number;
    recvBuf: Uint8Array;
    httpHandled: boolean;
    srcIp: string;
    srcPort: number;
    dstIp: string;
    dstPort: number;
    srcMac: Uint8Array;
    send: (flags: number, data?: Uint8Array) => void;
    constructor(opts: {
        srcIp: string;
        srcPort: number;
        dstIp: string;
        dstPort: number;
        srcMac: Uint8Array;
        send: (flags: number, data?: Uint8Array) => void;
    });
}
//# sourceMappingURL=TcpConn.d.ts.map