// JSVirtualGatewayProvider.ts — Drop-in EmulatorEthernetProvider for JSVirtualGateway
// Implements the same interface as CloudflareWorkerEthernetProvider.
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var __classPrivateFieldSet = (this && this.__classPrivateFieldSet) || function (receiver, state, value, kind, f) {
    if (kind === "m") throw new TypeError("Private method is not writable");
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
    return (kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value)), value;
};
var _JSVirtualGatewayProvider_gateway, _JSVirtualGatewayProvider_delegate, _JSVirtualGatewayProvider_macAddress;
import { JSVirtualGateway } from './JSVirtualGateway.js';
export class JSVirtualGatewayProvider {
    constructor(proxyBaseUrl) {
        _JSVirtualGatewayProvider_gateway.set(this, void 0);
        _JSVirtualGatewayProvider_delegate.set(this, void 0);
        _JSVirtualGatewayProvider_macAddress.set(this, void 0);
        __classPrivateFieldSet(this, _JSVirtualGatewayProvider_gateway, new JSVirtualGateway(proxyBaseUrl, (packet) => {
            __classPrivateFieldGet(this, _JSVirtualGatewayProvider_delegate, "f")?.receive(packet);
        }), "f");
    }
    description() {
        return 'JS Virtual Gateway';
    }
    macAddress() {
        return __classPrivateFieldGet(this, _JSVirtualGatewayProvider_macAddress, "f");
    }
    init(macAddress) {
        __classPrivateFieldSet(this, _JSVirtualGatewayProvider_macAddress, macAddress, "f");
        __classPrivateFieldGet(this, _JSVirtualGatewayProvider_gateway, "f").setMacAddress(macAddress);
        console.log(`[gw] init mac=${macAddress}`);
    }
    send(_destination, packet) {
        __classPrivateFieldGet(this, _JSVirtualGatewayProvider_gateway, "f").handleFrame(packet);
    }
    setDelegate(delegate) {
        __classPrivateFieldSet(this, _JSVirtualGatewayProvider_delegate, delegate, "f");
    }
    close() {
        // Nothing to close — no WebSocket
    }
}
_JSVirtualGatewayProvider_gateway = new WeakMap(), _JSVirtualGatewayProvider_delegate = new WeakMap(), _JSVirtualGatewayProvider_macAddress = new WeakMap();
//# sourceMappingURL=JSVirtualGatewayProvider.js.map