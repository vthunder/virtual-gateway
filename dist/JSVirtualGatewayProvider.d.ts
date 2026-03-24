export interface EmulatorEthernetProviderDelegate {
    receive(packet: Uint8Array): void;
}
export interface EmulatorEthernetProvider {
    init(macAddress: string): void;
    close?(): void;
    send(destination: string, packet: Uint8Array): void;
    setDelegate(delegate: EmulatorEthernetProviderDelegate): void;
    description(): string;
    macAddress(): string | undefined;
}
export declare class JSVirtualGatewayProvider implements EmulatorEthernetProvider {
    #private;
    constructor(proxyBaseUrl: string);
    description(): string;
    macAddress(): string | undefined;
    init(macAddress: string): void;
    send(_destination: string, packet: Uint8Array): void;
    setDelegate(delegate: EmulatorEthernetProviderDelegate): void;
    close(): void;
}
//# sourceMappingURL=JSVirtualGatewayProvider.d.ts.map