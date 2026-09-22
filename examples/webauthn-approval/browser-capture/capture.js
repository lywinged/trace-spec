// One approval artifact from a real browser: Chromium's WebAuthn stack with a DevTools
// virtual authenticator (CTAP2, internal transport, user verification on). The challenge
// is SHA-256 over the RFC 8785 form of {profile, approval}, as the profile specifies;
// RFC 8785 serializes primitives exactly as ECMAScript JSON.stringify does, so sorting keys
// by UTF-16 code units and stringifying the rest is RFC 8785 for this ASCII object.
const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const { chromium } = require("playwright");

const PROFILE = "tag:agentrust-io.com,2026:webauthn-approval-v1";
const b64u = (buf) => Buffer.from(buf).toString("base64url");
function jcs(v) {
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  if (v && typeof v === "object") {
    return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
  }
  return JSON.stringify(v);
}

(async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end("<!doctype html><title>approve</title><p>approval ceremony</p>");
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  const origin = `http://localhost:${port}`;

  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || undefined });
  const context = await browser.newContext();
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2", transport: "internal", hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
    },
  });
  await page.goto(origin + "/");

  // Registration: the relying party's side of it, reduced to what the registry records.
  const reg = await page.evaluate(async () => {
    const cred = await navigator.credentials.create({ publicKey: {
      rp: { id: "localhost", name: "approvals" },
      user: { id: new Uint8Array([1, 2, 3, 4]), name: "ops-lead", displayName: "Ops Lead" },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { userVerification: "required", residentKey: "discouraged" },
      attestation: "none",
    }});
    const r = cred.response;
    return {
      rawId: Array.from(new Uint8Array(cred.rawId)),
      spki: Array.from(new Uint8Array(r.getPublicKey())),
      alg: r.getPublicKeyAlgorithm(),
      authData: Array.from(new Uint8Array(r.getAuthenticatorData())),
      userAgent: navigator.userAgent,
    };
  });
  const credentialId = b64u(Buffer.from(reg.rawId));
  const jwk = crypto.createPublicKey({ key: Buffer.from(reg.spki), format: "der", type: "spki" }).export({ format: "jwk" });
  const regAuth = Buffer.from(reg.authData);
  const regFlags = regAuth[32];
  const regCount = regAuth.readUInt32BE(33);

  // The approval, and the challenge derived from it.
  const now = Math.floor(Date.now() / 1000);
  const approval = {
    approval_id: "approval/browser-capture",
    decision: "allow",
    approver: "approver-ops-lead",
    credential_id: credentialId,
    rp_id: "localhost",
    origin,
    subject_kind: "pic-trace-bridge-authorization",
    subject_digest: "sha256:" + crypto.createHash("sha256").update("browser-capture subject").digest("hex"),
    nonce: b64u(crypto.randomBytes(16)),
    issued_at: now,
    expires_at: now + 600,
  };
  const challenge = crypto.createHash("sha256").update(jcs({ profile: PROFILE, approval })).digest();

  const got = await page.evaluate(async ({ challenge, rawId }) => {
    const cred = await navigator.credentials.get({ publicKey: {
      challenge: new Uint8Array(challenge), rpId: "localhost",
      allowCredentials: [{ type: "public-key", id: new Uint8Array(rawId) }],
      userVerification: "required",
    }});
    const r = cred.response;
    return {
      authenticatorData: Array.from(new Uint8Array(r.authenticatorData)),
      clientDataJSON: Array.from(new Uint8Array(r.clientDataJSON)),
      signature: Array.from(new Uint8Array(r.signature)),
    };
  }, { challenge: Array.from(challenge), rawId: reg.rawId });

  const artifact = {
    profile: PROFILE,
    approval,
    assertion: {
      authenticator_data: b64u(Buffer.from(got.authenticatorData)),
      client_data_json: b64u(Buffer.from(got.clientDataJSON)),
      signature: b64u(Buffer.from(got.signature)),
      alg: reg.alg,
    },
  };
  const credential = {
    public_key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
    alg: reg.alg,
    rp_id: "localhost",
    origins: [origin],
    approver: "approver-ops-lead",
    attestation: "self-asserted",
    backup_eligible: Boolean(regFlags & 0x08),
    sign_count: regCount,
  };
  const context_ = {
    now: now + 5,
    clock_skew_seconds: 0,
    policy: { require_uv_for_deny: false },
    supported_algorithms: [-7, -8],
    credentials: { [credentialId]: credential },
    identity: { "approver-ops-lead": "https://idp.example.org/users/ops-lead" },
  };
  const out = {
    id: "browser-capture",
    description: "One artifact captured from Chromium's WebAuthn stack with a DevTools virtual authenticator (CTAP2, internal, user verification). Not part of the corpus and not reproducible byte for byte: the key, the nonce and the times are fresh on every run.",
    user_agent: reg.userAgent,
    captured_at: new Date(now * 1000).toISOString(),
    context: context_,
    artifact,
    client_data_decoded: JSON.parse(Buffer.from(got.clientDataJSON).toString("utf8")),
  };
  fs.writeFileSync("browser-capture.json", JSON.stringify(out, null, 2) + "\n");
  console.log(JSON.stringify({ user_agent: reg.userAgent, client_data: out.client_data_decoded,
    reg_flags: regFlags, reg_count: regCount, assertion_flags: got.authenticatorData[32],
    assertion_count: Buffer.from(got.authenticatorData).readUInt32BE(33), alg: reg.alg }, null, 1));
  await browser.close();
  server.close();
})().catch((e) => { console.error(e); process.exit(1); });
