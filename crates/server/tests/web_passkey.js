// The web client's side of `tests/web_passkey.rs` (E1-08.4), evaluated in a page served by the
// Core itself (same origin), so WebAuthn and WebCrypto run as a real web client's would. Test
// fixture, not a client: just enough of handshake spec §5 and §9 to drive the real routes.
window.ak = (() => {
  const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const unb64 = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  const enc = new TextEncoder();
  const sha = async (bytes) => b64(await crypto.subtle.digest("SHA-256", bytes));
  const post = async (path, body) => {
    const r = await fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    return { status: r.status, body: await r.json().catch(() => null) };
  };
  const state = {};

  // A signed request (§5.2) with the session key.
  async function signed(method, path, body) {
    const text = body === undefined ? "" : JSON.stringify(body);
    const ts = Math.floor(Date.now() / 1000).toString();
    const nonce = b64(crypto.getRandomValues(new Uint8Array(16)));
    const canonical = ["AINKRAD-REQ-V1", state.coreFp, "ES256", state.device, state.session,
      method, path, "", ts, nonce, await sha(enc.encode(text))].join("\n");
    const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, state.key.privateKey, enc.encode(canonical));
    const headers = { "Ainkrad-Device": state.device, "Ainkrad-Session": state.session, "Ainkrad-Alg": "ES256",
      "Ainkrad-Timestamp": ts, "Ainkrad-Nonce": nonce, "Ainkrad-Signature": b64(sig) };
    if (text) headers["content-type"] = "application/json";
    const r = await fetch(path, { method, headers, body: text || undefined });
    return { status: r.status, body: await r.json().catch(() => null) };
  }

  function requestOptions(o) {
    const pk = o.publicKey;
    pk.challenge = unb64(pk.challenge);
    pk.allowCredentials = (pk.allowCredentials || []).map((c) => ({ ...c, id: unb64(c.id) }));
    return { publicKey: pk };
  }

  function assertion(c) {
    return { id: c.id, rawId: b64(c.rawId), type: c.type, extensions: {},
      response: { authenticatorData: b64(c.response.authenticatorData), clientDataJSON: b64(c.response.clientDataJSON),
        signature: b64(c.response.signature), userHandle: c.response.userHandle ? b64(c.response.userHandle) : null } };
  }

  return {
    // Pairing with the code an admin device created (§9): options, create, claim.
    async pair(code) {
      const o = await post("/pair/passkey/options", { code });
      if (o.status !== 200) return o;
      const pk = o.body.options.publicKey;
      pk.challenge = unb64(pk.challenge);
      pk.user.id = unb64(pk.user.id);
      pk.excludeCredentials = (pk.excludeCredentials || []).map((c) => ({ ...c, id: unb64(c.id) }));
      const c = await navigator.credentials.create({ publicKey: pk });
      const credential = { id: c.id, rawId: b64(c.rawId), type: c.type, extensions: {},
        response: { attestationObject: b64(c.response.attestationObject), clientDataJSON: b64(c.response.clientDataJSON),
          transports: c.response.getTransports ? c.response.getTransports() : [] } };
      return post("/pair/passkey/claim", { code, credential, platform: "chromium" });
    },
    // Sign-in (§9): a non-extractable session key, its SPKI in the options, a UV assertion.
    async signIn() {
      const h = await (await fetch("/handshake")).json();
      state.coreFp = h.identity_fingerprint;
      state.key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
      const spki = b64(await crypto.subtle.exportKey("spki", state.key.publicKey));
      const o = await post("/handshake/passkey/options", { session_spki: spki });
      if (o.status !== 200) return o;
      const c = await navigator.credentials.get(requestOptions(o.body.options));
      const g = await post("/handshake/passkey/session", { credential: assertion(c) });
      if (g.status === 200) { state.device = g.body.device_id; state.session = g.body.session_id; }
      return { ...g, extractable: state.key.privateKey.extractable };
    },
    signed,
    // Step-up (§8): an assertion over this session's challenge.
    async stepUp() {
      const ch = await signed("POST", "/api/v1/auth/step-up/challenge");
      if (ch.status !== 200) return ch;
      const c = await navigator.credentials.get(requestOptions(ch.body.options));
      return signed("POST", "/api/v1/auth/step-up", { challenge: ch.body.challenge, assertion: assertion(c) });
    },
    // The event socket with a one-time ticket (§10); resolves once open.
    async socket() {
      const t = await signed("POST", "/api/v1/ws-ticket");
      if (t.status !== 200) return t;
      state.closed = new Promise((done) => {
        const ws = new WebSocket(`ws://${location.host}/api/v1/events/ws`, ["ainkrad.v1", "ainkrad-ticket." + t.body.ticket]);
        state.opened = new Promise((ok, fail) => { ws.onopen = () => ok(ws.protocol); ws.onerror = () => fail("error"); });
        ws.onclose = (e) => done(e.code);
      });
      return { status: 101, protocol: await state.opened };
    },
    closed: () => state.closed,
  };
})();
