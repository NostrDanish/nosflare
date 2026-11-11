import assert from "node:assert/strict";
import { schnorr } from "@noble/curves/secp256k1.js";

const baseUrl = (process.env.RELAY_URL || "https://nosflare-0xserverless-v8.0xprivacy-online.workers.dev").replace(/\/$/, "");
const wsUrl = baseUrl.replace(/^https:/, "wss:").replace(/^http:/, "ws:");
const secret1 = new Uint8Array(32);
secret1[31] = 1;
const secret2 = new Uint8Array(32);
secret2[31] = 2;
const toHex = (bytes) => Buffer.from(bytes).toString("hex");
const pubkey1 = toHex(schnorr.getPublicKey(secret1));
const pubkey2 = toHex(schnorr.getPublicKey(secret2));

assert.equal(pubkey1, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
assert.equal(pubkey2, "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");

async function makeEvent(secretKey, kind, tags, content, createdAt) {
  const pubkey = toHex(schnorr.getPublicKey(secretKey));
  const serialized = JSON.stringify([0, pubkey, createdAt, kind, tags, content]);
  const idBytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(serialized)));
  return {
    id: toHex(idBytes),
    pubkey,
    created_at: createdAt,
    kind,
    tags,
    content,
    sig: toHex(schnorr.sign(idBytes, secretKey)),
  };
}

function parseFrame(data) {
  return JSON.parse(String(data));
}

function waitForFrame(socket, predicate, timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error("Timed out waiting for relay response")), timeoutMs);
    const onMessage = (event) => {
      let frame;
      try { frame = parseFrame(event.data); } catch (error) { finish(error); return; }
      if (predicate(frame)) finish(null, frame);
    };
    const onError = () => finish(new Error("WebSocket error while waiting for relay response"));
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

async function publish(socket, event, expectedAccepted) {
  const response = waitForFrame(socket, frame => frame[0] === "OK" && frame[1] === event.id);
  socket.send(JSON.stringify(["EVENT", event]));
  const frame = await response;
  assert.equal(frame[2], expectedAccepted, `unexpected EVENT result for kind ${event.kind}: ${frame[3]}`);
  return frame;
}

async function queryById(socket, id) {
  const subId = `smoke-${id.slice(0, 10)}`;
  return new Promise((resolve, reject) => {
    const events = [];
    const timer = setTimeout(() => finish(new Error("Timed out waiting for EOSE")), 20000);
    const onMessage = (message) => {
      let frame;
      try { frame = parseFrame(message.data); } catch (error) { finish(error); return; }
      if (frame[0] === "EVENT" && frame[1] === subId) events.push(frame[2]);
      if (frame[0] === "EOSE" && frame[1] === subId) finish(null, events);
      if (frame[0] === "NOTICE" && /error/i.test(String(frame[1]))) finish(new Error(String(frame[1])));
    };
    function finish(error, result) {
      clearTimeout(timer);
      socket.removeEventListener("message", onMessage);
      try { socket.send(JSON.stringify(["CLOSE", subId])); } catch {}
      if (error) reject(error);
      else resolve(result);
    }
    socket.addEventListener("message", onMessage);
    socket.send(JSON.stringify(["REQ", subId, { ids: [id], limit: 5 }]));
  });
}

const socket = new WebSocket(wsUrl);
await new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error("WebSocket connection timed out")), 15000);
  socket.addEventListener("open", () => { clearTimeout(timer); resolve(); }, { once: true });
  socket.addEventListener("error", () => { clearTimeout(timer); reject(new Error("Could not connect to staging relay WebSocket")); }, { once: true });
});

try {
  const now = Math.floor(Date.now() / 1000) + 2;

  // Ownership: another pubkey's deletion request must not delete this event.
  const foreignTarget = await makeEvent(secret2, 1, [], "staging ownership test", now);
  await publish(socket, foreignTarget, true);
  const foreignDelete = await makeEvent(secret1, 5, [["e", foreignTarget.id]], "", now + 1);
  await publish(socket, foreignDelete, true);
  assert.equal((await queryById(socket, foreignTarget.id)).length, 1, "foreign author must not delete another author's event");

  // NIP-09 e-tag deletion, including prevention of later re-publication.
  const ownDelete = await makeEvent(secret2, 5, [["e", foreignTarget.id]], "", now + 2);
  await publish(socket, ownDelete, true);
  assert.equal((await queryById(socket, foreignTarget.id)).length, 0, "NIP-09 e-tag target should be removed");
  const republishE = await publish(socket, foreignTarget, false);
  assert.match(String(republishE[3]), /deleted/i, "deleted e-tag event must not be resurrected");

  // NIP-09 a-tag deletion for a parameterized replaceable event.
  const dTag = `stage:article:${now}`;
  const article = await makeEvent(secret1, 30023, [["d", dTag]], "staging addressable deletion test", now + 3);
  await publish(socket, article, true);
  const deleteAddress = await makeEvent(secret1, 5, [["a", `30023:${pubkey1}:${dTag}`]], "", now + 4);
  await publish(socket, deleteAddress, true);
  assert.equal((await queryById(socket, article.id)).length, 0, "NIP-09 a-tag target should be removed");
  const republishA = await publish(socket, article, false);
  assert.match(String(republishA[3]), /deleted/i, "deleted a-tag event must not be resurrected");

  // NIP-01 replaceable tie-break: equal timestamps retain the lower event id.
  const tieA = await makeEvent(secret1, 10001, [], "replaceable-A", now + 5);
  const tieB = await makeEvent(secret1, 10001, [], "replaceable-B", now + 5);
  const winner = tieA.id < tieB.id ? tieA : tieB;
  const loser = winner === tieA ? tieB : tieA;
  await publish(socket, winner, true);
  await publish(socket, loser, false);
  assert.equal((await queryById(socket, winner.id)).length, 1, "preferred replaceable event should remain");
  assert.equal((await queryById(socket, loser.id)).length, 0, "non-winning replaceable event should not be stored");

  // NIP-33 replacement by (kind, pubkey, d-tag).
  const replaceD = `stage:replace:${now}`;
  const newer = await makeEvent(secret1, 30023, [["d", replaceD]], "newer version", now + 7);
  const older = await makeEvent(secret1, 30023, [["d", replaceD]], "older version", now + 6);
  await publish(socket, newer, true);
  await publish(socket, older, false);
  assert.equal((await queryById(socket, newer.id)).length, 1, "newer NIP-33 event should remain");
  assert.equal((await queryById(socket, older.id)).length, 0, "older NIP-33 event should not be stored");

  // Empty d-tags must be normalized consistently (NULL and empty string).
  const emptyDNewer = await makeEvent(secret1, 30024, [["d", ""]], "empty d newer", now + 9);
  const emptyDOlder = await makeEvent(secret1, 30024, [["d", ""]], "empty d older", now + 8);
  await publish(socket, emptyDNewer, true);
  await publish(socket, emptyDOlder, false);
  assert.equal((await queryById(socket, emptyDNewer.id)).length, 1, "empty d-tag coordinate should be stored");
  assert.equal((await queryById(socket, emptyDOlder.id)).length, 0, "empty d-tag coordinate should replace older version");

  console.log("Staging write-path tests passed: author ownership, NIP-09 e/a deletion and tombstones, NIP-01 ordering, NIP-33 and empty d-tags.");
} finally {
  socket.close();
}
