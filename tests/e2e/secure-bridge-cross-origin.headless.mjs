import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import https from "node:https";
import os from "node:os";
import path from "node:path";

import { firstBridgeStartupURL, writeTestCertificate } from "./remote-ssh-test-harness.mjs";

const repoRoot = process.cwd();
const bridgeRoot = path.join(repoRoot, "bridge");
const bridgePort = Number(process.env.LOCALDRAFTAI_SECURE_BRIDGE_PORT || 8792);
const frontendPort = Number(process.env.LOCALDRAFTAI_SECURE_FRONTEND_PORT || 8793);
const adminDebugPort = Number(process.env.LOCALDRAFTAI_SECURE_ADMIN_DEBUG_PORT || 9262);
const clientDebugPort = Number(process.env.LOCALDRAFTAI_SECURE_CLIENT_DEBUG_PORT || 9263);

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitForHttp(url, allowCertificate = false, timeoutMs = 15000) {
  const started = Date.now();
  let lastError;
  while (Date.now() - started < timeoutMs) {
    try {
      if (url.startsWith("https:")) {
        const status = await new Promise((resolve, reject) => {
          const request = https.get(url, { rejectUnauthorized: !allowCertificate }, (response) => {
            response.resume();
            resolve(response.statusCode || 0);
          });
          request.on("error", reject);
        });
        if (status >= 200 && status < 400) return;
      } else if ((await fetch(url)).ok) return;
    } catch (error) { lastError = error; }
    await delay(100);
  }
  throw lastError || new Error(`Timed out waiting for ${url}`);
}

function buildBridge(output) {
  const result = spawnSync("go", ["build", "-o", output, "./cmd/localdraft-bridge"], { cwd: bridgeRoot, encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr || result.stdout);
}

function startChrome(profile, debugPort, url) {
  return spawn("google-chrome", [
    "--headless=new", "--disable-gpu", "--no-sandbox", "--ignore-certificate-errors",
    `--remote-debugging-port=${debugPort}`, `--user-data-dir=${profile}`, url
  ], { stdio: "ignore" });
}

async function connectPage(debugPort) {
  await waitForHttp(`http://127.0.0.1:${debugPort}/json`);
  const pages = await (await fetch(`http://127.0.0.1:${debugPort}/json`)).json();
  const page = pages.find((entry) => entry.type === "page");
  const socket = new WebSocket(page.webSocketDebuggerUrl);
  const pending = new Map();
  let id = 0;
  socket.onmessage = (event) => {
    const message = JSON.parse(event.data);
    if (message.id && pending.has(message.id)) {
      pending.get(message.id)(message);
      pending.delete(message.id);
    }
  };
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
  const send = (method, params = {}) => new Promise((resolve) => {
    const next = ++id;
    pending.set(next, resolve);
    socket.send(JSON.stringify({ id: next, method, params }));
  });
  await send("Runtime.enable");
  return { send, socket };
}

async function evaluate(page, expression) {
  const response = await page.send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
  if (response.result.exceptionDetails) throw new Error(response.result.exceptionDetails.text || "Evaluation failed");
  return response.result.result.value;
}

async function waitFor(page, expression, timeoutMs = 15000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await evaluate(page, expression)) return;
    await delay(100);
  }
  throw new Error(`Timed out waiting for ${expression}`);
}

async function stop(child) {
  if (!child || child.exitCode !== null) return;
  child.kill();
  await Promise.race([new Promise((resolve) => child.once("exit", resolve)), delay(2000)]);
  if (child.exitCode === null) child.kill("SIGKILL");
}

function contentType(file) {
  if (file.endsWith(".html")) return "text/html; charset=utf-8";
  if (file.endsWith(".js") || file.endsWith(".mjs")) return "text/javascript; charset=utf-8";
  if (file.endsWith(".css")) return "text/css; charset=utf-8";
  if (file.endsWith(".ico")) return "image/x-icon";
  return "application/octet-stream";
}

async function main() {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "localdraftai-secure-cross-origin-"));
  const bridgeBinary = path.join(tempRoot, "localdraft-bridge");
  const configDir = path.join(tempRoot, "config");
  const tls = writeTestCertificate(tempRoot);
  const frontendOrigin = `https://127.0.0.1:${frontendPort}`;
  const endpoint = `wss://127.0.0.1:${bridgePort}/api/bridge`;
  let bridgeProcess;
  let adminChrome;
  let clientChrome;
  let frontendServer;
  let adminPage;
  let clientPage;

  try {
    buildBridge(bridgeBinary);
    bridgeProcess = spawn(bridgeBinary, [
      "serve", "--listen", `127.0.0.1:${bridgePort}`,
      "--public-origin", `https://127.0.0.1:${bridgePort}`,
      "--tls-cert", tls.certificate, "--tls-key", tls.key,
      "--web-root", repoRoot, "--config-dir", configDir
    ], { stdio: ["ignore", "pipe", "inherit"] });
    const startupUrl = await firstBridgeStartupURL(bridgeProcess);
    await waitForHttp(`https://127.0.0.1:${bridgePort}/api/health`, true);

    frontendServer = https.createServer({ cert: fs.readFileSync(tls.certificate), key: fs.readFileSync(tls.key) }, (request, response) => {
      const requested = new URL(request.url, frontendOrigin).pathname;
      const relative = requested.replace(/^\//, "");
      const target = path.resolve(repoRoot, relative);
      if (!target.startsWith(repoRoot + path.sep) || !fs.existsSync(target) || !fs.statSync(target).isFile()) {
        response.writeHead(404).end("Not found");
        return;
      }
      response.setHeader("Content-Type", contentType(target));
      response.end(fs.readFileSync(target));
    });
    await new Promise((resolve) => frontendServer.listen(frontendPort, "127.0.0.1", resolve));

    adminChrome = startChrome(path.join(tempRoot, "admin-profile"), adminDebugPort, startupUrl.href);
    adminPage = await connectPage(adminDebugPort);
    await waitFor(adminPage, `Boolean(window.MarkdownEditor && window.MarkdownEditor.activeBridgeClient && window.MarkdownEditor.activeBridgeClient.getClaims().admin)`);
    await evaluate(adminPage, `window.MarkdownEditor.activeBridgeClient.request("bridge.security.addAllowedOrigin", {origin:${JSON.stringify(frontendOrigin)}})`);

    clientChrome = startChrome(path.join(tempRoot, "client-profile"), clientDebugPort, `${frontendOrigin}/src/local_draft_ai.html?e2e`);
    clientPage = await connectPage(clientDebugPort);
    await waitFor(clientPage, `Boolean(window.MarkdownEditor && window.MarkdownEditor.__testApi)`);
    await evaluate(clientPage, `localStorage.setItem("localdraft.bridge.endpoint.v1", ${JSON.stringify(endpoint)}); location.reload()`);
    await waitFor(clientPage, `window.MarkdownEditor && window.MarkdownEditor.bridgeDetectionError && window.MarkdownEditor.bridgeDetectionError.code === "PAIRING_REQUIRED"`);

    const pending = await evaluate(adminPage, `window.MarkdownEditor.activeBridgeClient.request("bridge.security.listPairingRequests", {})`);
    assert.equal(pending.requests.length, 1);
    assert.equal(pending.requests[0].origin, frontendOrigin);
    await evaluate(adminPage, `window.MarkdownEditor.activeBridgeClient.request("bridge.security.approvePairingRequest", {requestId:${JSON.stringify(pending.requests[0].requestId)}})`);
    await waitFor(clientPage, `Boolean(window.MarkdownEditor.activeBridgeClient && window.MarkdownEditor.activeBridgeClient.getState() === "connected")`);

    const normalAccess = await evaluate(clientPage, `window.MarkdownEditor.activeBridgeClient.request("bridge.getStatus", {})`);
    assert.equal(normalAccess.status, "ready");
    assert.equal(await evaluate(clientPage, `window.MarkdownEditor.activeBridgeClient.getClaims().admin`), false);
    assert.equal(await evaluate(clientPage, `window.MarkdownEditor.activeBridgeClient.request("bridge.security.getSettings", {}).then(() => "allowed", error => error.code)`), "FORBIDDEN");

    const clientId = await evaluate(clientPage, `window.MarkdownEditor.activeBridgeClient.getClaims().clientId`);
    await evaluate(adminPage, `window.MarkdownEditor.activeBridgeClient.request("bridge.security.revokePairedClient", {clientId:${JSON.stringify(clientId)}})`);
    await waitFor(clientPage, `window.MarkdownEditor.activeBridgeClient.getState() === "disconnected"`);
    await evaluate(clientPage, `location.reload()`);
    await waitFor(clientPage, `window.MarkdownEditor && window.MarkdownEditor.bridgeDetectionError && window.MarkdownEditor.bridgeDetectionError.code === "PAIRING_REQUIRED"`);

    await evaluate(adminPage, `window.MarkdownEditor.activeBridgeClient.request("bridge.security.removeAllowedOrigin", {origin:${JSON.stringify(frontendOrigin)}})`);
    await evaluate(clientPage, `location.reload()`);
    await waitFor(clientPage, `window.MarkdownEditor && window.MarkdownEditor.bridgeDetectionError && window.MarkdownEditor.bridgeDetectionError.code === "BRIDGE_UNAVAILABLE"`);

    console.log("ok - cross-origin HTTPS frontend pairs over WSS, remains non-admin, and honors revocation and origin removal");
  } finally {
    if (adminPage) adminPage.socket.close();
    if (clientPage) clientPage.socket.close();
    await stop(clientChrome);
    await stop(adminChrome);
    await stop(bridgeProcess);
    if (frontendServer) await new Promise((resolve) => frontendServer.close(resolve));
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error("not ok - secure cross-origin bridge");
  console.error(error);
  process.exitCode = 1;
});
