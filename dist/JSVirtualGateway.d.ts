export declare class JSVirtualGateway {
    #private;
    constructor(proxyBaseUrl: string, send: (p: Uint8Array) => void);
    setMacAddress(mac: string): void;
    handleFrame(frame: Uint8Array): void;
}
//# sourceMappingURL=JSVirtualGateway.d.ts.map