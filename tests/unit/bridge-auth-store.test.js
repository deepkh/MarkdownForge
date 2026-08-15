const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");

global.window = {
  atob: (value) => Buffer.from(value, "base64").toString("binary"),
  btoa: (value) => Buffer.from(value, "binary").toString("base64"),
  crypto: webcrypto,
  navigator: { platform: "Linux x86_64", userAgent: "Chrome/140" }
};
require("../../src/js/bridge-auth-store.js");

const bridgeAuthStore = window.MarkdownEditor.bridgeAuthStore;
const records = new Map();
const adapter = {
  async get(key) { return records.get(key) || null; },
  async put(value) { records.set(value.endpoint, value); return value; }
};

(async function () {
  const endpoint = "wss://bridge.example.test:4782/api/bridge";
  const store = bridgeAuthStore.create({ adapter, crypto: webcrypto, navigator: window.navigator });
  const identity = await store.getIdentity(endpoint);
  assert.equal(identity.privateKey.extractable, false);
  assert.equal(identity.privateKey.type, "private");
  await assert.rejects(webcrypto.subtle.exportKey("jwk", identity.privateKey));

  const restored = await bridgeAuthStore.create({ adapter, crypto: webcrypto, navigator: window.navigator }).getIdentity(endpoint);
  assert.equal(restored.clientId, identity.clientId);
  assert.equal(restored.privateKey, identity.privateKey);

  const publicIdentity = await store.publicIdentity(endpoint);
  assert.equal(publicIdentity.publicKey.kty, "EC");
  assert.equal(publicIdentity.publicKey.crv, "P-256");
  assert.match(publicIdentity.name, /^Chrome on Linux/);

  const challengeBytes = webcrypto.getRandomValues(new Uint8Array(32));
  const challenge = bridgeAuthStore.base64UrlEncode(challengeBytes);
  const signature = bridgeAuthStore.base64UrlDecode(await store.sign(endpoint, challenge));
  assert.equal(await webcrypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    identity.publicKey,
    signature,
    challengeBytes
  ), true);

  console.log("ok - creates, persists, restores, and signs with a non-exportable bridge browser key");
}()).catch(function (error) {
  console.error("not ok - bridge auth store");
  throw error;
});
