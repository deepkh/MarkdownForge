(function () {
  "use strict";

  var ME = window.MarkdownEditor = window.MarkdownEditor || {};
  var DATABASE_NAME = "localdraftai-bridge-auth";
  var STORE_NAME = "identities";

  function base64UrlEncode(bytes) {
    var binary = "";
    var view = new Uint8Array(bytes);
    var index;
    for (index = 0; index < view.length; index += 1) {
      binary += String.fromCharCode(view[index]);
    }
    return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function base64UrlDecode(value) {
    var normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
    var binary;
    var bytes;
    var index;
    normalized += "=".repeat((4 - normalized.length % 4) % 4);
    binary = window.atob(normalized);
    bytes = new Uint8Array(binary.length);
    for (index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  }

  function openDatabase(indexedDBValue) {
    return new Promise(function (resolve, reject) {
      var request = indexedDBValue.open(DATABASE_NAME, 1);
      request.onupgradeneeded = function () {
        if (!request.result.objectStoreNames.contains(STORE_NAME)) {
          request.result.createObjectStore(STORE_NAME, { keyPath: "endpoint" });
        }
      };
      request.onsuccess = function () { resolve(request.result); };
      request.onerror = function () { reject(request.error || new Error("Could not open the bridge identity store.")); };
    });
  }

  function databaseGet(database, endpoint) {
    return new Promise(function (resolve, reject) {
      var request = database.transaction(STORE_NAME, "readonly").objectStore(STORE_NAME).get(endpoint);
      request.onsuccess = function () { resolve(request.result || null); };
      request.onerror = function () { reject(request.error || new Error("Could not read the bridge identity.")); };
    });
  }

  function databasePut(database, value) {
    return new Promise(function (resolve, reject) {
      var request = database.transaction(STORE_NAME, "readwrite").objectStore(STORE_NAME).put(value);
      request.onsuccess = function () { resolve(value); };
      request.onerror = function () { reject(request.error || new Error("Could not save the bridge identity.")); };
    });
  }

  function browserName(navigatorValue) {
    var platform = navigatorValue && navigatorValue.platform || "Browser";
    var agent = navigatorValue && navigatorValue.userAgent || "";
    var browser = /Firefox/i.test(agent) ? "Firefox" : /Edg\//i.test(agent) ? "Edge" : /Chrome/i.test(agent) ? "Chrome" : /Safari/i.test(agent) ? "Safari" : "Browser";
    return browser + (platform ? " on " + platform : "");
  }

  function create(options) {
    options = options || {};
    var cryptoValue = options.crypto || window.crypto;
    var indexedDBValue = options.indexedDB || window.indexedDB;
    var navigatorValue = options.navigator || window.navigator;
    var adapter = options.adapter || null;

    if (!cryptoValue || !cryptoValue.subtle) {
      throw new Error("WebCrypto is required for LocalDraft Bridge authentication.");
    }

    async function read(endpoint) {
      var database;
      if (adapter) return adapter.get(endpoint);
      if (!indexedDBValue) throw new Error("IndexedDB is required for LocalDraft Bridge authentication.");
      database = await openDatabase(indexedDBValue);
      try { return await databaseGet(database, endpoint); } finally { database.close(); }
    }

    async function write(value) {
      var database;
      if (adapter) return adapter.put(value);
      database = await openDatabase(indexedDBValue);
      try { return await databasePut(database, value); } finally { database.close(); }
    }

    async function getIdentity(endpoint) {
      var stored = await read(endpoint);
      var keyPair;
      var identity;
      if (stored && stored.privateKey && stored.publicKey && stored.clientId) {
        return stored;
      }
      keyPair = await cryptoValue.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
      identity = {
        endpoint: endpoint,
        clientId: cryptoValue.randomUUID ? cryptoValue.randomUUID() : "client-" + Date.now() + "-" + Math.random().toString(16).slice(2),
        name: browserName(navigatorValue),
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        createdAt: new Date().toISOString()
      };
      await write(identity);
      return identity;
    }

    async function publicIdentity(endpoint) {
      var identity = await getIdentity(endpoint);
      var publicKey = await cryptoValue.subtle.exportKey("jwk", identity.publicKey);
      return {
        clientId: identity.clientId,
        name: identity.name,
        publicKey: { kty: publicKey.kty, crv: publicKey.crv, x: publicKey.x, y: publicKey.y }
      };
    }

    async function sign(endpoint, challenge) {
      var identity = await getIdentity(endpoint);
      var bytes = base64UrlDecode(challenge);
      var signature = await cryptoValue.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, identity.privateKey, bytes);
      return base64UrlEncode(signature);
    }

    return { getIdentity: getIdentity, publicIdentity: publicIdentity, sign: sign };
  }

  ME.bridgeAuthStore = {
    DATABASE_NAME: DATABASE_NAME,
    STORE_NAME: STORE_NAME,
    base64UrlDecode: base64UrlDecode,
    base64UrlEncode: base64UrlEncode,
    create: create
  };
}());
