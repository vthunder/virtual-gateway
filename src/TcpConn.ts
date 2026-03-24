// TcpConn.ts — TCP connection state

export type TcpConnState = 'SYN_RECEIVED' | 'ESTABLISHED' | 'FIN_SENT' | 'CLOSED';

export class TcpConn {
  state: TcpConnState = 'SYN_RECEIVED';
  serverSeq: number;
  clientSeq: number = 0;
  recvBuf: Uint8Array = new Uint8Array(0);
  httpHandled: boolean = false;

  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  srcMac: Uint8Array;

  // Bound send function — set by JSVirtualGateway
  send: (flags: number, data?: Uint8Array) => void;

  constructor(opts: {
    srcIp: string;
    srcPort: number;
    dstIp: string;
    dstPort: number;
    srcMac: Uint8Array;
    send: (flags: number, data?: Uint8Array) => void;
  }) {
    this.srcIp = opts.srcIp;
    this.srcPort = opts.srcPort;
    this.dstIp = opts.dstIp;
    this.dstPort = opts.dstPort;
    this.srcMac = opts.srcMac;
    this.send = opts.send;
    this.serverSeq = ((Math.random() * 0x7fffffff) | 0) >>> 0;
  }
}
