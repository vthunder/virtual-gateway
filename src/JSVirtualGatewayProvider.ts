// JSVirtualGatewayProvider.ts — Drop-in EmulatorEthernetProvider for JSVirtualGateway
// Implements the same interface as CloudflareWorkerEthernetProvider.

import { JSVirtualGateway } from './JSVirtualGateway.js';

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

export class JSVirtualGatewayProvider implements EmulatorEthernetProvider {
  #gateway: JSVirtualGateway;
  #delegate?: EmulatorEthernetProviderDelegate;
  #macAddress?: string;

  constructor(proxyBaseUrl: string) {
    this.#gateway = new JSVirtualGateway(proxyBaseUrl, (packet) => {
      this.#delegate?.receive(packet);
    });
  }

  description(): string {
    return 'JS Virtual Gateway';
  }

  macAddress(): string | undefined {
    return this.#macAddress;
  }

  init(macAddress: string): void {
    this.#macAddress = macAddress;
    this.#gateway.setMacAddress(macAddress);
    console.log(`[gw] init mac=${macAddress}`);
  }

  send(_destination: string, packet: Uint8Array): void {
    this.#gateway.handleFrame(packet);
  }

  setDelegate(delegate: EmulatorEthernetProviderDelegate): void {
    this.#delegate = delegate;
  }

  close(): void {
    // Nothing to close — no WebSocket
  }
}
