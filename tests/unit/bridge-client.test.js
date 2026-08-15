const assert = require("node:assert/strict");

global.window = {
  clearTimeout,
  setTimeout,
  URL,
  crypto: require("node:crypto").webcrypto,
  localStorage: null,
  location: { protocol: "https:", host: "bridge.example.test:4782" }
};
require("../../src/js/storage-provider-registry.js");
require("../../src/js/bridge-client.js");

const bridgeClient = window.MarkdownEditor.bridgeClient;
const authStore = {
  async publicIdentity() {
    return { clientId: "client-1", name: "Test Browser", publicKey: { kty: "EC", crv: "P-256", x: "x", y: "y" } };
  },
  async sign(endpoint, challenge) {
    assert.equal(endpoint, "wss://bridge.example.test:4782/api/bridge");
    assert.equal(challenge, "challenge");
    return "signature";
  }
};

class FakeWebSocket {
  static OPEN = 1;
  static CLOSING = 2;
  static instances = [];

  constructor(url) {
    this.url = url;
    this.readyState = 0;
    this.protocolVersion = 2;
    this.pairingRequired = false;
    FakeWebSocket.instances.push(this);
    queueMicrotask(() => {
      this.readyState = FakeWebSocket.OPEN;
      this.onopen();
    });
  }

  send(value) {
    const request = JSON.parse(value);
    queueMicrotask(() => {
      let result = {};
      if (request.method === "bridge.auth.begin") {
        if (this.pairingRequired) {
          this.onmessage({ data: JSON.stringify({ jsonrpc: "2.0", id: request.id, error: {
            code: -32041,
            message: "Pair this browser.",
            data: { code: "PAIRING_REQUIRED", retryable: true, details: { requestId: "pair-1", code: "483219" } }
          } }) });
          return;
        }
        result = { challenge: "challenge" };
      } else if (request.method === "bridge.auth.complete") {
        result = { status: "authenticated", claims: { clientId: "client-1", origin: "https://bridge.example.test:4782", admin: true } };
      } else if (request.method === "bridge.hello") {
        result = { protocolVersion: this.protocolVersion, bridgeVersion: "0.2.0" };
      } else if (request.method === "bridge.getStatus") {
        result = { status: "ready" };
      } else if (request.method === "fail") {
        this.onmessage({ data: JSON.stringify({
          jsonrpc: "2.0", id: request.id,
          error: { code: -32020, message: "Disconnected", data: { code: "CONNECTION_LOST", retryable: true } }
        }) });
        return;
      }
      this.onmessage({ data: JSON.stringify({ jsonrpc: "2.0", id: request.id, result }) });
    });
  }

  close() {
    this.readyState = FakeWebSocket.CLOSING;
    if (this.onclose) this.onclose();
  }

  notify(method, params) {
    this.onmessage({ data: JSON.stringify({ jsonrpc: "2.0", method, params }) });
  }
}

(async function () {
  assert.equal(bridgeClient.PROTOCOL_VERSION, 2);
  assert.equal(
    bridgeClient.normalizeEndpoint("wss://Bridge.Example.Test:4782/"),
    "wss://bridge.example.test:4782/api/bridge"
  );
  assert.throws(() => bridgeClient.normalizeEndpoint("ws://bridge.example.test:4782/api/bridge"), (error) => error.code === "INVALID_BRIDGE_ENDPOINT");
  assert.equal(bridgeClient.sameOriginEndpoint(window.location), "wss://bridge.example.test:4782/api/bridge");

  const client = bridgeClient.create({ WebSocketImpl: FakeWebSocket, location: window.location, authStore, timeoutMs: 500 });
  const hello = await client.connect();
  assert.equal(hello.protocolVersion, 2);
  assert.equal(client.getState(), "connected");
  assert.equal(client.getClaims().admin, true);
  assert.equal((await client.request("bridge.getStatus")).status, "ready");

  let notification = null;
  client.on("connection.stateChanged", (params) => { notification = params; });
  FakeWebSocket.instances[0].notify("connection.stateChanged", { state: "disconnected" });
  assert.deepEqual(notification, { state: "disconnected" });
  await assert.rejects(client.request("fail"), (error) => error.code === "CONNECTION_LOST" && error.retryable === true);
  client.close();

  class MismatchWebSocket extends FakeWebSocket {
    constructor(url) { super(url); this.protocolVersion = 1; }
  }
  const mismatch = bridgeClient.create({ WebSocketImpl: MismatchWebSocket, location: window.location, authStore, timeoutMs: 500 });
  await assert.rejects(mismatch.connect(), (error) => error.code === "BRIDGE_PROTOCOL_MISMATCH");

  const storage = {
    value: "wss://bridge.example.test:4782/api/bridge",
    getItem() { return this.value; },
    setItem(key, value) { assert.equal(key, bridgeClient.ENDPOINT_STORAGE_KEY); this.value = value; },
    removeItem() { this.value = ""; }
  };
  let fetchCalls = 0;
  const configured = await bridgeClient.detect({
    storage,
    fetchImpl: async () => { fetchCalls += 1; throw new Error("must not fetch"); },
    WebSocketImpl: FakeWebSocket,
    authStore
  });
  assert.equal(configured.getState(), "connected");
  assert.equal(fetchCalls, 0);

  storage.value = "";
  const sameOrigin = await bridgeClient.detect({
    storage,
    location: window.location,
    fetchImpl: async () => ({ ok: true, async json() { return { protocolVersion: 2 }; } }),
    WebSocketImpl: FakeWebSocket,
    authStore
  });
  assert.equal(sameOrigin.url, "wss://bridge.example.test:4782/api/bridge");

  const hostedAbsent = await bridgeClient.detect({
    storage,
    location: { protocol: "https:", host: "localdraft.ai" },
    fetchImpl: async () => ({ ok: false }),
    WebSocketImpl: FakeWebSocket,
    authStore
  });
  assert.equal(hostedAbsent, null);

  class PairingWebSocket extends FakeWebSocket {
    constructor(url) { super(url); this.pairingRequired = true; }
  }
  const pairingClient = bridgeClient.create({ WebSocketImpl: PairingWebSocket, location: window.location, authStore, timeoutMs: 500 });
  await assert.rejects(pairingClient.connect(), (error) => error.code === "PAIRING_REQUIRED");
  assert.equal(pairingClient.getState(), "pairing-required");
  assert.equal(pairingClient.getPairing().code, "483219");

  console.log("ok - resolves WSS endpoints and authenticates, pairs, and reports bridge RPC state");
}()).catch(function (error) {
  console.error("not ok - bridge client");
  throw error;
});
