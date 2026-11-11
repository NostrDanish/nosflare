import assert from "node:assert/strict";

const baseUrl = (process.env.RELAY_URL || "https://nosflare-0xserverless-v8.0xprivacy-online.workers.dev").replace(/\/$/, "");

const infoResponse = await fetch(baseUrl, {
  headers: { Accept: "application/nostr+json" },
  signal: AbortSignal.timeout(15000),
});
assert.equal(infoResponse.status, 200, "NIP-11 endpoint must return HTTP 200");
assert.match(infoResponse.headers.get("content-type") || "", /application\/nostr\+json/i);
const info = await infoResponse.json();

assert.equal(info.software, "https://github.com/NostrDanish/nosflare");
assert.equal(info.version, "8.9.27");
assert.equal(info.limitation?.max_content_length, 70000);
assert.ok(Array.isArray(info.supported_nips));
assert.ok(!info.supported_nips.includes(40), "must not advertise unimplemented NIP-40");
assert.ok(!info.supported_nips.includes(50), "must not advertise unimplemented NIP-50");

const wsUrl = baseUrl.replace(/^https:/, "wss:").replace(/^http:/, "ws:");
const socket = new WebSocket(wsUrl);
await new Promise((resolve, reject) => {
  let finished = false;
  const timeout = setTimeout(() => finish(new Error("WebSocket REQ timed out before EOSE")), 20000);

  function finish(error) {
    if (finished) return;
    finished = true;
    clearTimeout(timeout);
    try { socket.close(); } catch {}
    if (error) reject(error);
    else resolve();
  }

  socket.addEventListener("open", () => {
    socket.send(JSON.stringify(["REQ", "staging-smoke", { limit: 1 }]));
  });

  socket.addEventListener("message", (message) => {
    let payload;
    try {
      payload = JSON.parse(String(message.data));
    } catch (error) {
      finish(error);
      return;
    }
    if (payload[0] === "EOSE" && payload[1] === "staging-smoke") finish();
    if (payload[0] === "NOTICE" && /error/i.test(String(payload[1]))) {
      finish(new Error(`Relay NOTICE: ${payload[1]}`));
    }
  });

  socket.addEventListener("error", () => finish(new Error("WebSocket connection failed")));
  socket.addEventListener("close", (event) => {
    if (!finished) finish(new Error(`WebSocket closed before EOSE (code ${event.code})`));
  });
});

console.log("Staging smoke test passed: NIP-11 metadata and WebSocket REQ/EOSE.");
