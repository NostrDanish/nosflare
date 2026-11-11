import assert from "node:assert/strict";
import { schnorr } from "@noble/curves/secp256k1.js";

const baseUrl = (process.env.RELAY_URL || "https://nosflare-0xserverless-v8.0xprivacy-online.workers.dev").replace(/\/$/, "");
const wsUrl = baseUrl.replace(/^https:/, "wss:").replace(/^http:/, "ws:");
const secretKey = new Uint8Array(32);
secretKey[31] = 1;
const toHex = (bytes) => Buffer.from(bytes).toString("hex");

async function makeEvent(kind, tags, content, createdAt) {
  const pubkey = toHex(schnorr.getPublicKey(secretKey));
  const serialized = JSON.stringify([0, pubkey, createdAt, kind, tags, content]);
  const idBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(serialized)));
  return {
    id: toHex(idBytes), pubkey, created_at: createdAt, kind, tags, content,
    sig: toHex(schnorr.sign(idBytes, secretKey)),
  };
}

function waitForFrame(socket, predicate, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error("Timed out waiting for relay response")), timeoutMs);
    const onMessage = (event) => {
      let frame;
      try { frame = JSON.parse(String(event.data)); } catch (error) { finish(error); return; }
      if (predicate(frame)) finish(null, frame);
    };
    const onError = () => finish(new Error("WebSocket error"));
    function finish(error, frame) {
      clearTimeout(timer);
      socket.removeEventListener("message", onMessage);
      socket.removeEventListener("error", onError);
      if (error) reject(error);
      else resolve(frame);
    }
    socket.addEventListener("message", onMessage);
    socket.addEventListener("error", onError);
  });
}

const infoResponse = await fetch(baseUrl, {
  headers: { Accept: "application/nostr+json" },
  signal: AbortSignal.timeout(15000),
});
assert.equal(infoResponse.status, 200, "NIP-11 endpoint must return HTTP 200");
assert.match(infoResponse.headers.get("content-type") || "", /application\/nostr\+json/i);
const info = await infoResponse.json();

assert.equal(info.software, "https://github.com/NostrDanish/nosflare");
assert.equal(info.version, "8.9.28");
assert.equal(info.limitation?.max_content_length, 70000);
assert.equal(info.limitation?.auth_required, true, "must preserve production NIP-42 authentication");
assert.equal(info.limitation?.payment_required, true, "must preserve pay-to-relay policy");
assert.ok(Array.isArray(info.supported_nips));
assert.ok(info.supported_nips.includes(42));
assert.ok(!info.supported_nips.includes(40), "must not advertise unimplemented NIP-40");
assert.ok(!info.supported_nips.includes(50), "must not advertise unimplemented NIP-50");

const socket = new WebSocket(wsUrl);
const challengePromise = waitForFrame(socket, frame => frame[0] === "AUTH");
await new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error("WebSocket connection timed out")), 15000);
  socket.addEventListener("open", () => { clearTimeout(timer); resolve(); }, { once: true });
  socket.addEventListener("error", () => { clearTimeout(timer); reject(new Error("WebSocket connection failed")); }, { once: true });
});

try {
  const challenge = await challengePromise;
  assert.equal(typeof challenge[1], "string");
  const authEvent = await makeEvent(22242, [
    ["relay", wsUrl],
    ["challenge", challenge[1]],
  ], "", Math.floor(Date.now() / 1000));
  const authResultPromise = waitForFrame(socket, frame => frame[0] === "OK" && frame[1] === authEvent.id);
  socket.send(JSON.stringify(["AUTH", authEvent]));
  const authResult = await authResultPromise;
  assert.equal(authResult[2], true, `NIP-42 AUTH rejected: ${authResult[3]}`);

  const eosePromise = waitForFrame(socket, frame => frame[0] === "EOSE" && frame[1] === "staging-smoke");
  socket.send(JSON.stringify(["REQ", "staging-smoke", { limit: 1 }]));
  await eosePromise;
  socket.send(JSON.stringify(["CLOSE", "staging-smoke"]));

  console.log("Staging smoke test passed: NIP-11 metadata, NIP-42 AUTH, and WebSocket REQ/EOSE.");
} finally {
  socket.close();
}
