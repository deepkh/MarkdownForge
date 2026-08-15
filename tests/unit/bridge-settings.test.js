const assert = require("node:assert/strict");

global.window = { MarkdownEditor: {}, URL };
require("../../src/js/bridge-settings.js");

const bridgeSettings = window.MarkdownEditor.bridgeSettings;

assert.equal(bridgeSettings.formatPairingCode("483219"), "483 219");
assert.equal(
  bridgeSettings.bridgeSiteUrl("wss://bridge.example.test:4782/api/bridge"),
  "https://bridge.example.test:4782/src/local_draft_ai.html"
);
assert.deepEqual(bridgeSettings.originRows({
  selfOrigin: "https://bridge.example.test:4782",
  allowedOrigins: ["https://localdraft.ai", "https://bridge.example.test:4782", "https://dev.localdraft.ai"]
}), [
  { origin: "https://bridge.example.test:4782", builtIn: true },
  { origin: "https://localdraft.ai", builtIn: false },
  { origin: "https://dev.localdraft.ai", builtIn: false }
]);

console.log("ok - formats pairing state and keeps the bridge self origin built-in and non-removable");
