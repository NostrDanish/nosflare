import test from "node:test";
import assert from "node:assert/strict";
import { bolt11AmountMsats, npubToHex, verifyZapReceipt } from "../src/zap-verification";

const OPERATOR_NPUB = "npub1c3gyzcvf2xakqy4vy06umu7hgpr97ttyp05yrlvmk8g8xvmse57qj286r6";
const OPERATOR_HEX = "c45041618951bb6012ac23f5cdf3d740465f2d640be841fd9bb1d0733370cd3c";
const ISSUER_HEX = "beeb48407a6f087ea8f76dc384a5d88c67ced9bd9fb0cdba90930210df3d92e7";
const OTHER_ISSUER_HEX = "e".repeat(64);
const PAYER_HEX = "a".repeat(64);
const PRICE_SATS = 5000;
const INVOICE = "lnbc50u1exampleinvoice";

function makeZapRequest(overrides: Record<string, unknown> = {}) {
  return {
    id: "1".repeat(64),
    pubkey: PAYER_HEX,
    created_at: Math.floor(Date.now() / 1000),
    kind: 9734,
    tags: [
      ["p", OPERATOR_HEX],
      ["amount", String(PRICE_SATS * 1000)],
      ["relays", "wss://relay.damus.io"],
    ],
    content: "Relay access",
    sig: "2".repeat(128),
    ...overrides,
  };
}

function makeReceipt(overrides: Record<string, unknown> = {}) {
  const request = makeZapRequest();
  return {
    id: "b".repeat(64),
    pubkey: ISSUER_HEX,
    created_at: Math.floor(Date.now() / 1000),
    kind: 9735,
    tags: [
      ["p", OPERATOR_HEX],
      ["bolt11", INVOICE],
      ["description", JSON.stringify(request)],
    ],
    content: "",
    sig: "c".repeat(128),
    ...overrides,
  };
}

async function verify(
  receipt: any,
  issuer = ISSUER_HEX,
  verifier: (event: any) => Promise<boolean> = async () => true
) {
  return verifyZapReceipt(receipt, OPERATOR_NPUB, PRICE_SATS, verifier, issuer);
}

test("operator npub decodes to the exact configured relay pubkey", () => {
  assert.equal(npubToHex(OPERATOR_NPUB), OPERATOR_HEX);
});

test("decodes BOLT11 amount units to millisatoshis", () => {
  assert.equal(bolt11AmountMsats("lnbc50u1invoice"), 5_000_000);
  assert.equal(bolt11AmountMsats("lnbc5m1invoice"), 500_000_000);
  assert.equal(bolt11AmountMsats("lnbc500000n1invoice"), 50_000_000);
  assert.equal(bolt11AmountMsats("lnbc50000000p1invoice"), 5_000_000);
  assert.equal(bolt11AmountMsats("lnbc1p1invoice"), null);
  assert.equal(bolt11AmountMsats("lnbc1unknown"), null);
  assert.equal(bolt11AmountMsats("lnbc1"), null);
});

test("accepts a standard NIP-57 receipt without the optional P tag or a non-standard amount tag", async () => {
  const result = await verify(makeReceipt());
  assert.deepEqual(result && {
    payer: result.payer,
    amountSats: result.amountSats,
    receiptId: result.receiptId,
    bolt11: result.bolt11,
  }, {
    payer: PAYER_HEX,
    amountSats: PRICE_SATS,
    receiptId: "b".repeat(64),
    bolt11: INVOICE,
  });
});

test("accepts an optional receipt P tag when it matches the signed zap request author", async () => {
  const receipt = makeReceipt({
    tags: [
      ["p", OPERATOR_HEX],
      ["P", PAYER_HEX],
      ["bolt11", INVOICE],
      ["description", JSON.stringify(makeZapRequest())],
    ],
  });
  assert.equal((await verify(receipt))?.payer, PAYER_HEX);
});

test("rejects a self-signed receipt from an untrusted issuer", async () => {
  assert.equal(await verify(makeReceipt(), OTHER_ISSUER_HEX), null);
});

test("fails closed when neither a trusted issuer key nor payee address is configured", async () => {
  assert.equal(await verifyZapReceipt(
    makeReceipt() as any,
    OPERATOR_NPUB,
    PRICE_SATS,
    async () => true,
    "",
    ""
  ), null);
});

test("rejects invalid receipt signatures and invalid zap request signatures", async () => {
  assert.equal(await verify(makeReceipt(), ISSUER_HEX, async () => false), null);
  assert.equal(await verify(makeReceipt(), ISSUER_HEX, async (event) => event.kind !== 9734), null);
});

test("rejects wrong receipt kind, missing description, wrong recipient and malformed request", async () => {
  assert.equal(await verify(makeReceipt({ kind: 9734 })), null);
  assert.equal(await verify(makeReceipt({
    tags: [["p", OPERATOR_HEX], ["bolt11", INVOICE]],
  })), null);
  assert.equal(await verify(makeReceipt({
    tags: [["p", "1".repeat(64)], ["bolt11", INVOICE], ["description", JSON.stringify(makeZapRequest())]],
  })), null);
  assert.equal(await verify(makeReceipt({
    tags: [["p", OPERATOR_HEX], ["bolt11", INVOICE], ["description", "{not-json"]],
  })), null);
});

test("rejects wrong zap request recipient and a mismatched optional P tag", async () => {
  const wrongRecipient = makeZapRequest({
    tags: [["p", "1".repeat(64)], ["amount", "5000000"]],
  });
  assert.equal(await verify(makeReceipt({
    tags: [["p", OPERATOR_HEX], ["bolt11", INVOICE], ["description", JSON.stringify(wrongRecipient)]],
  })), null);

  const receipt = makeReceipt({
    tags: [
      ["p", OPERATOR_HEX],
      ["P", "d".repeat(64)],
      ["bolt11", INVOICE],
      ["description", JSON.stringify(makeZapRequest())],
    ],
  });
  assert.equal(await verify(receipt), null);
});

test("rejects underpayment, invoice/request amount mismatch and malformed request amount", async () => {
  const underpaid = makeReceipt({
    tags: [["p", OPERATOR_HEX], ["bolt11", "lnbc49u1invoice"], ["description", JSON.stringify(makeZapRequest({
      tags: [["p", OPERATOR_HEX], ["amount", "4900000"]],
    }))]],
  });
  assert.equal(await verify(underpaid), null);

  const mismatch = makeReceipt();
  assert.equal(await verify({
    ...mismatch,
    tags: mismatch.tags.map((tag: string[]) => tag[0] === "description"
      ? ["description", JSON.stringify(makeZapRequest({ tags: [["p", OPERATOR_HEX], ["amount", "4999999"]] }))]
      : tag),
  }), null);

  const malformed = makeReceipt();
  assert.equal(await verify({
    ...malformed,
    tags: malformed.tags.map((tag: string[]) => tag[0] === "description"
      ? ["description", JSON.stringify(makeZapRequest({ tags: [["p", OPERATOR_HEX], ["amount", "5000000msat"]] }))]
      : tag),
  }), null);
});

test("rejects amountless invoices and zap requests older than 24 hours", async () => {
  const receipt = makeReceipt();
  assert.equal(await verify({
    ...receipt,
    tags: receipt.tags.map((tag: string[]) => tag[0] === "bolt11" ? ["bolt11", "lnbc1invoice"] : tag),
  }), null);

  const staleRequest = makeZapRequest({ created_at: Math.floor(Date.now() / 1000) - 25 * 3600 });
  assert.equal(await verify({
    ...receipt,
    tags: receipt.tags.map((tag: string[]) => tag[0] === "description"
      ? ["description", JSON.stringify(staleRequest)]
      : tag),
  }), null);
});

test("rejects stale and excessively future-dated zap receipts", async () => {
  const now = Math.floor(Date.now() / 1000);
  assert.equal(await verify(makeReceipt({ created_at: now - 31 * 24 * 3600 })), null);
  assert.equal(await verify(makeReceipt({ created_at: now + 16 * 60 })), null);
});
