(function () {
  "use strict";

  var ME = window.MarkdownEditor = window.MarkdownEditor || {};
  var PROTOCOL_VERSION = 2;
  var ENDPOINT_STORAGE_KEY = "localdraft.bridge.endpoint.v1";

  function bridgeError(code, message, options) {
    if (ME.storageProviderErrors) return ME.storageProviderErrors.create(code, message, options);
    var error = new Error(message);
    error.name = "StorageProviderError";
    error.code = code;
    error.retryable = Boolean(options && options.retryable);
    error.details = options && options.details || {};
    return error;
  }

  function normalizeEndpoint(value, URLImpl) {
    var parsed;
    URLImpl = URLImpl || window.URL;
    try { parsed = new URLImpl(String(value || "").trim()); } catch (error) {
      throw bridgeError("INVALID_BRIDGE_ENDPOINT", "Enter a valid WSS LocalDraft Bridge endpoint.");
    }
    if (parsed.protocol !== "wss:" || parsed.username || parsed.password || parsed.search || parsed.hash) {
      throw bridgeError("INVALID_BRIDGE_ENDPOINT", "Bridge endpoints must use wss:// without credentials, query parameters, or fragments.");
    }
    if (parsed.pathname === "" || parsed.pathname === "/") parsed.pathname = "/api/bridge";
    if (parsed.pathname.replace(/\/$/, "") !== "/api/bridge") {
      throw bridgeError("INVALID_BRIDGE_ENDPOINT", "The bridge endpoint path must be /api/bridge.");
    }
    parsed.pathname = "/api/bridge";
    return parsed.href;
  }

  function sameOriginEndpoint(locationValue) {
    if (!locationValue || locationValue.protocol !== "https:" || !locationValue.host) return "";
    return "wss://" + locationValue.host + "/api/bridge";
  }

  function configuredEndpoint(storage, URLImpl) {
    var value;
    try { value = storage && storage.getItem(ENDPOINT_STORAGE_KEY); } catch (error) { value = ""; }
    if (!value) return "";
    return normalizeEndpoint(value, URLImpl);
  }

  function storeEndpoint(value, storage, URLImpl) {
    var normalized = normalizeEndpoint(value, URLImpl);
    if (!storage) throw bridgeError("BRIDGE_UNAVAILABLE", "Browser storage is unavailable.");
    storage.setItem(ENDPOINT_STORAGE_KEY, normalized);
    return normalized;
  }

  function clearEndpoint(storage) {
    if (storage) storage.removeItem(ENDPOINT_STORAGE_KEY);
  }

  function requestId() {
    if (window.crypto && typeof window.crypto.randomUUID === "function") return window.crypto.randomUUID();
    return "request-" + Date.now() + "-" + Math.random().toString(16).slice(2);
  }

  function connectionDiagnostic() {
    return "Could not connect to LocalDraft Bridge. Check the bridge URL, TLS certificate trust, Allowed Frontend Origins, network/firewall access, and browser local-network permission.";
  }

  function create(options) {
    options = options || {};
    var WebSocketImpl = options.WebSocketImpl || window.WebSocket;
    var url = normalizeEndpoint(options.url || sameOriginEndpoint(options.location || window.location), options.URLImpl);
    var authStore = options.authStore || (ME.bridgeAuthStore && ME.bridgeAuthStore.create(options.authOptions));
    var timeoutMs = Math.max(100, Number(options.timeoutMs) || 10000);
    var socket = null;
    var pending = {};
    var listeners = {};
    var state = "disconnected";
    var hello = null;
    var claims = null;
    var pairing = null;
    var connecting = null;

    function emit(method, params) {
      (listeners[method] || []).slice().forEach(function (listener) { listener(params); });
      (listeners["*"] || []).slice().forEach(function (listener) { listener({ method: method, params: params }); });
    }

    function setState(next, details) {
      state = next;
      emit("bridge.stateChanged", Object.assign({ state: state }, details || {}));
    }

    function rejectPending(error) {
      Object.keys(pending).forEach(function (id) {
        window.clearTimeout(pending[id].timer);
        pending[id].reject(error);
        delete pending[id];
      });
    }

    function handleMessage(event) {
      var message;
      var waiting;
      try { message = JSON.parse(event.data); } catch (error) { return; }
      if (message && message.id != null) {
        waiting = pending[String(message.id)];
        if (!waiting) return;
        window.clearTimeout(waiting.timer);
        delete pending[String(message.id)];
        if (message.error) {
          waiting.reject(bridgeError(
            message.error.data && message.error.data.code || "BRIDGE_UNAVAILABLE",
            message.error.message || "The LocalDraft Bridge request failed.",
            { retryable: Boolean(message.error.data && message.error.data.retryable), details: message.error.data && message.error.data.details || {} }
          ));
          return;
        }
        waiting.resolve(message.result);
        return;
      }
      if (message && message.method) emit(message.method, message.params || {});
    }

    function request(method, params, requestOptions) {
      var id;
      var callTimeout;
      if (!socket || socket.readyState !== WebSocketImpl.OPEN) {
        return Promise.reject(bridgeError("BRIDGE_UNAVAILABLE", "The LocalDraft Bridge is not connected.", { retryable: true }));
      }
      id = requestId();
      callTimeout = Math.max(100, Number(requestOptions && requestOptions.timeoutMs) || timeoutMs);
      return new Promise(function (resolve, reject) {
        pending[id] = {
          reject: reject,
          resolve: resolve,
          timer: window.setTimeout(function () {
            delete pending[id];
            reject(bridgeError("BRIDGE_UNAVAILABLE", "The LocalDraft Bridge request timed out.", { retryable: true }));
          }, callTimeout)
        };
        socket.send(JSON.stringify({ jsonrpc: "2.0", id: id, method: method, params: params || {} }));
      });
    }

    async function authenticate() {
      var identity;
      var beginning;
      var signature;
      var completed;
      if (!authStore) throw bridgeError("BRIDGE_AUTH_UNAVAILABLE", "Secure browser identity storage is unavailable.");
      identity = await authStore.publicIdentity(url);
      try {
        beginning = await request("bridge.auth.begin", identity);
      } catch (error) {
        if (error.code === "PAIRING_REQUIRED") {
          pairing = Object.assign({ endpoint: url }, error.details || {});
          setState("pairing-required", { pairing: pairing });
        }
        throw error;
      }
      signature = await authStore.sign(url, beginning.challenge);
      completed = await request("bridge.auth.complete", { signature: signature });
      claims = completed && completed.claims || null;
      pairing = null;
    }

    async function finishConnection() {
      await authenticate();
      hello = await request("bridge.hello", {});
      if (!hello || Number(hello.protocolVersion) !== PROTOCOL_VERSION) {
        close();
        throw bridgeError("BRIDGE_PROTOCOL_MISMATCH", "This LocalDraft Bridge version is not compatible with the browser app.", {
          details: { expected: PROTOCOL_VERSION, received: hello && hello.protocolVersion }
        });
      }
      claims = hello.claims || claims;
      setState("connected");
      return hello;
    }

    async function connect() {
      if (!WebSocketImpl) throw bridgeError("BRIDGE_UNAVAILABLE", "WebSocket support is unavailable.");
      if (state === "connected") return hello;
      if (state === "pairing-required" && socket && socket.readyState === WebSocketImpl.OPEN) return retryPairing();
      if (connecting) return connecting;
      setState("connecting");
      connecting = (async function () {
        socket = new WebSocketImpl(url);
        socket.onmessage = handleMessage;
        socket.onclose = function () {
          setState("disconnected");
          rejectPending(bridgeError("BRIDGE_UNAVAILABLE", "The LocalDraft Bridge connection closed.", { retryable: true }));
        };
        await new Promise(function (resolve, reject) {
          var timer = window.setTimeout(function () {
            reject(bridgeError("BRIDGE_UNAVAILABLE", connectionDiagnostic(), { retryable: true }));
          }, timeoutMs);
          socket.onopen = function () { window.clearTimeout(timer); resolve(); };
          socket.onerror = function () {
            window.clearTimeout(timer);
            reject(bridgeError("BRIDGE_UNAVAILABLE", connectionDiagnostic(), { retryable: true }));
          };
        });
        return finishConnection();
      }());
      try { return await connecting; } finally { connecting = null; }
    }

    async function retryPairing() {
      if (!socket || socket.readyState !== WebSocketImpl.OPEN) return connect();
      setState("connecting");
      return finishConnection();
    }

    function close() {
      if (socket && socket.readyState < WebSocketImpl.CLOSING) socket.close(1000, "browser client closed");
      setState("disconnected");
    }

    function on(method, listener) {
      listeners[method] = listeners[method] || [];
      listeners[method].push(listener);
      return function () { listeners[method] = (listeners[method] || []).filter(function (item) { return item !== listener; }); };
    }

    return {
      close: close,
      connect: connect,
      getClaims: function () { return claims; },
      getHello: function () { return hello; },
      getPairing: function () { return pairing; },
      getState: function () { return state; },
      on: on,
      request: request,
      retryPairing: retryPairing,
      url: url
    };
  }

  async function detect(options) {
    options = options || {};
    var locationValue = options.location || window.location;
    var fetchImpl = options.fetchImpl || window.fetch;
    var storage = options.storage || window.localStorage;
    var endpoint = options.url ? normalizeEndpoint(options.url, options.URLImpl) : configuredEndpoint(storage, options.URLImpl);
    var response;
    var health;
    var client;

    if (!endpoint) {
      if (!sameOriginEndpoint(locationValue) || !fetchImpl) return null;
      try {
        response = await fetchImpl("/api/health", { cache: "no-store", credentials: "same-origin" });
        if (!response || !response.ok) return null;
        health = await response.json();
      } catch (error) { return null; }
      if (Number(health.protocolVersion) !== PROTOCOL_VERSION) {
        throw bridgeError("BRIDGE_PROTOCOL_MISMATCH", "This LocalDraft Bridge version is not compatible with the browser app.", {
          details: { expected: PROTOCOL_VERSION, received: health.protocolVersion }
        });
      }
      endpoint = sameOriginEndpoint(locationValue);
    }
    client = create(Object.assign({}, options, { url: endpoint }));
    try {
      await client.connect();
    } catch (error) {
      error.client = client;
      throw error;
    }
    return client;
  }

  ME.bridgeClient = {
    ENDPOINT_STORAGE_KEY: ENDPOINT_STORAGE_KEY,
    PROTOCOL_VERSION: PROTOCOL_VERSION,
    clearEndpoint: clearEndpoint,
    configuredEndpoint: configuredEndpoint,
    create: create,
    detect: detect,
    normalizeEndpoint: normalizeEndpoint,
    sameOriginEndpoint: sameOriginEndpoint,
    storeEndpoint: storeEndpoint
  };
}());
