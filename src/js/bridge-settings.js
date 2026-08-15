(function () {
  "use strict";

  var ME = window.MarkdownEditor = window.MarkdownEditor || {};

  function formatPairingCode(value) {
    value = String(value || "").replace(/\D/g, "").slice(0, 6);
    return value.length > 3 ? value.slice(0, 3) + " " + value.slice(3) : value;
  }

  function bridgeSiteUrl(endpoint, URLImpl) {
    var parsed = new (URLImpl || window.URL)(endpoint);
    parsed.protocol = "https:";
    parsed.pathname = "/src/local_draft_ai.html";
    parsed.search = "";
    parsed.hash = "";
    return parsed.href;
  }

  function originRows(settings) {
    settings = settings || {};
    return [{ origin: settings.selfOrigin || settings.publicOrigin || "", builtIn: true }].concat(
      (settings.allowedOrigins || []).filter(function (origin) { return origin !== settings.selfOrigin; }).map(function (origin) {
        return { origin: origin, builtIn: false };
      })
    );
  }

  function create(context) {
    context = context || {};
    var bridgeClient = context.bridgeClient || ME.bridgeClient;
    var overlay = context.overlay;
    var client = context.client || null;
    var pairingTimer = 0;
    var elements = context.elements || {};
    var storage = context.storage || window.localStorage;
    var locationValue = context.location || window.location;
    var onClientChange = context.onClientChange || function () {};

    function report(message, kind) {
      if (!elements.status) return;
      elements.status.textContent = message || "";
      elements.status.dataset.status = kind || "";
    }

    function setPairing(pairing) {
      if (!elements.pairingSection) return;
      elements.pairingSection.hidden = !pairing;
      if (!pairing) return;
      elements.pairingCode.textContent = formatPairingCode(pairing.code);
      elements.pairingOrigin.textContent = pairing.origin || "";
      elements.openBridge.dataset.endpoint = pairing.endpoint || elements.endpoint.value;
    }

    function stopPairingPoll() {
      if (pairingTimer) window.clearInterval(pairingTimer);
      pairingTimer = 0;
    }

    function startPairingPoll() {
      stopPairingPoll();
      if (!client || client.getState() !== "pairing-required") return;
      pairingTimer = window.setInterval(async function () {
        try {
          await client.retryPairing();
          stopPairingPoll();
          onClientChange(client);
          await loadAdminSecurity();
        } catch (retryError) {
          if (retryError.code !== "PAIRING_REQUIRED") {
            stopPairingPoll();
            report(retryError.message, "error");
          }
        }
      }, 3000);
    }

    function handleClientState(update) {
      if (update.state === "pairing-required") {
        setPairing(update.pairing || client.getPairing());
        report("Pairing required. Approve this browser from the bridge site.", "error");
      } else if (update.state === "connected") {
        stopPairingPoll();
        setPairing(null);
        report("Connected", "success");
      } else if (update.state === "connecting") {
        report("Connecting…", "");
      } else if (update.state === "disconnected") {
        report("Disconnected", "");
      }
    }

    async function loadAdminSecurity() {
      var settings;
      var paired;
      var pending;
      var claims = client && client.getClaims && client.getClaims();
      if (!elements.adminSection) return;
      elements.adminSection.hidden = !(claims && claims.admin);
      if (elements.adminSection.hidden) return;
      try {
        settings = await client.request("bridge.security.getSettings", {});
        paired = await client.request("bridge.security.listPairedClients", {});
        pending = await client.request("bridge.security.listPairingRequests", {});
        renderOrigins(settings);
        renderPairings(pending.requests || []);
        renderClients(paired.clients || []);
      } catch (error) {
        report(error.message || "Could not load bridge security settings.", "error");
      }
    }

    function button(label, action, value) {
      var result = document.createElement("button");
      result.type = "button";
      result.className = "file-button";
      result.textContent = label;
      result.dataset.bridgeAction = action;
      if (value) result.dataset.value = value;
      return result;
    }

    function renderOrigins(settings) {
      if (!elements.originList) return;
      elements.originList.innerHTML = "";
      originRows(settings).forEach(function (row) {
        var item = document.createElement("div");
        var label = document.createElement("span");
        item.className = "bridge-security-row";
        label.textContent = (row.builtIn ? "🔒 " : "") + row.origin + (row.builtIn ? "  Built-in" : "");
        item.appendChild(label);
        if (!row.builtIn) item.appendChild(button("Remove", "remove-origin", row.origin));
        elements.originList.appendChild(item);
      });
    }

    function renderPairings(requests) {
      if (!elements.pairingList) return;
      elements.pairingList.innerHTML = "";
      if (!requests.length) elements.pairingList.textContent = "No pending requests.";
      requests.forEach(function (request) {
        var item = document.createElement("div");
        var label = document.createElement("span");
        item.className = "bridge-security-row bridge-security-row-stacked";
        label.textContent = formatPairingCode(request.code) + " — " + request.name + " — " + request.origin;
        item.appendChild(label);
        item.appendChild(button("Allow", "approve-pairing", request.requestId));
        item.appendChild(button("Deny", "deny-pairing", request.requestId));
        elements.pairingList.appendChild(item);
      });
    }

    function renderClients(clients) {
      if (!elements.clientList) return;
      elements.clientList.innerHTML = "";
      if (!clients.length) elements.clientList.textContent = "No paired browsers.";
      clients.forEach(function (pairedClient) {
        var item = document.createElement("div");
        var label = document.createElement("span");
        item.className = "bridge-security-row bridge-security-row-stacked";
        label.textContent = pairedClient.name + " — " + pairedClient.origin + " — Last used: " + new Date(pairedClient.lastUsedAt).toLocaleString();
        item.appendChild(label);
        item.appendChild(button("Revoke", "revoke-client", pairedClient.id));
        elements.clientList.appendChild(item);
      });
    }

    async function connect() {
      var endpoint;
      stopPairingPoll();
      try {
        endpoint = bridgeClient.storeEndpoint(elements.endpoint.value, storage);
        if (client) client.close();
        client = bridgeClient.create({ url: endpoint, location: locationValue });
        client.on("bridge.stateChanged", handleClientState);
        await client.connect();
        onClientChange(client);
        await loadAdminSecurity();
      } catch (error) {
        if (client && error.code === "PAIRING_REQUIRED") {
          setPairing(client.getPairing());
          startPairingPoll();
        }
        report(error.message || "Could not connect to LocalDraft Bridge.", "error");
      }
    }

    function disconnect() {
      stopPairingPoll();
      if (client) client.close();
      client = null;
      onClientChange(null);
      setPairing(null);
      if (elements.adminSection) elements.adminSection.hidden = true;
      report("Disconnected", "");
    }

    async function securityAction(action, value) {
      var method;
      var params;
      if (action === "remove-origin") { method = "bridge.security.removeAllowedOrigin"; params = { origin: value }; }
      if (action === "approve-pairing") { method = "bridge.security.approvePairingRequest"; params = { requestId: value }; }
      if (action === "deny-pairing") { method = "bridge.security.denyPairingRequest"; params = { requestId: value }; }
      if (action === "revoke-client") { method = "bridge.security.revokePairedClient"; params = { clientId: value }; }
      if (!method || !client) return;
      try { await client.request(method, params); await loadAdminSecurity(); } catch (error) { report(error.message, "error"); }
    }

    function open() {
      var configured = "";
      try { configured = bridgeClient.configuredEndpoint(storage); } catch (error) { report(error.message, "error"); }
      elements.endpoint.value = configured || bridgeClient.sameOriginEndpoint(locationValue) || "";
      overlay.hidden = false;
      if (!client || !client.getClaims || !client.getClaims() || !client.getClaims().admin) {
        elements.adminSection.hidden = true;
      }
      setPairing(client && client.getPairing && client.getPairing());
      if (client && client.getState() === "connected") {
        report("Connected", "success");
        loadAdminSecurity();
      } else if (!elements.endpoint.value) report("Configure a WSS bridge endpoint.", "");
      elements.endpoint.focus();
    }

    function close() { overlay.hidden = true; stopPairingPoll(); }

    function bindEvents() {
      elements.connect.addEventListener("click", connect);
      elements.disconnect.addEventListener("click", disconnect);
      elements.close.addEventListener("click", close);
      elements.done.addEventListener("click", close);
      elements.openBridge.addEventListener("click", function () {
        window.open(bridgeSiteUrl(elements.openBridge.dataset.endpoint), "_blank", "noopener");
      });
      elements.addOrigin.addEventListener("click", async function () {
        var origin = elements.newOrigin.value;
        if (!client || !origin) return;
        try {
          await client.request("bridge.security.addAllowedOrigin", { origin: origin });
          elements.newOrigin.value = "";
          await loadAdminSecurity();
        } catch (error) { report(error.message, "error"); }
      });
      elements.adminSection.addEventListener("click", function (event) {
        var target = event.target.closest("[data-bridge-action]");
        if (target) securityAction(target.dataset.bridgeAction, target.dataset.value);
      });
      overlay.addEventListener("click", function (event) { if (event.target === overlay) close(); });
      document.addEventListener("keydown", function (event) { if (event.key === "Escape" && !overlay.hidden) close(); });
    }

    function setClient(next) {
      client = next || null;
      if (client && client.getState() === "pairing-required") {
        setPairing(client.getPairing());
        startPairingPoll();
      }
    }

    return { bindEvents: bindEvents, close: close, connect: connect, loadAdminSecurity: loadAdminSecurity, open: open, setClient: setClient };
  }

  ME.bridgeSettings = {
    bridgeSiteUrl: bridgeSiteUrl,
    create: create,
    formatPairingCode: formatPairingCode,
    originRows: originRows
  };
}());
