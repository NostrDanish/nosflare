import test from "node:test";
import assert from "node:assert/strict";
import { npubToHex, verifyZapReceipt } from "../src/zap-verification";

const OPERATOR_NPUB = "npub1c3gyzcvf2xakqy4vy06umu7hgpr97ttyp05yrlvmk8g8xvmse57qj286r6";
const OPERATOR_HEX = "c45041618951bb6012ac23f5cdf3d740465f2d640be841fd9bb1d0733370cd3c";
const ISSUER_HEX = "f".repeat(64);
const PAYER_HEX = "a".repeat(64);
const PRICE_SATS = 5000;

function makeReceipt(overrides: Record<string, unknown> = {}) {
  return {
    id: "b".repeat(64),
    pubkey: ISSUER_HEX,
    created_at: Math.floor(Date.now() / 1000),
    kind: 9735,
    tags: [
      ["p", OPERATOR_HEX],
      ["P", PAYER_HEX],
      ["amount", String(PRICE_SATS * 1000)],
      ["bolt11", "lnbc50u1exampleinvoice"],
    ],
    content: "",
    sig: "c".repeat(128),
    ...overrides,
  };
}

async function verify(receipt: any, issuer = ISSUER_HEX, signatureValid = true) {
  return verifyZapReceipt(
    receipt,
    OPERATOR_NPUB,
    PRICE_SATS,
    async () => signatureValid,
    issuer
  );
}

test("operator npub decodes to the exact configured relay pubkey", () => {
  assert.equal(npubToHex(OPERATOR_NPUB), OPERATOR_HEX);
});

test("accepts a receipt signed by the configured LNURL issuer and credits its P-tag payer", async () => {
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
    bolt11: "lnbc50u1exampleinvoice",
  });
});

test("rejects a self-signed receipt from an untrusted issuer", async () => {
  assert.equal(await verify(makeReceipt(), "e".repeat(64), true), null);
});

test("fails closed when neither a trusted issuer key nor payee address is configured", async () => {
  assert.equal(await verifyZapReceipt(
    makeReceipt(),
    OPERATOR_NPUB,
    PRICE_SATS,
    async () => true,
    "",
    ""
  ), null);
});

test("rejects invalid Schnorr signatures", async () => {
  assert.equal(await verify(makeReceipt(), ISSUER_HEX, false), null);
});

test("rejects wrong kind, wrong recipient, or missing payer", async () => {
  assert.equal(await verify(makeReceipt({ kind: 9734 })), null);
  assert.equal(await verify(makeReceipt({
    tags: [["p", "1".repeat(64)], ["P", PAYER_HEX], ["amount", "5000000"], ["bolt11", "lnbcinvoice"]]
  })), null);
  assert.equal(await verify(makeReceipt({
    tags: [["p", OPERATOR_HEX], ["amount", "5000000"], ["bolt11", "lnbcinvoice"]]
  })), null);
});

test("rejects underpayment, non-integer millisatoshi amounts, and missing invoices", async () => {
  assert.equal(await verify(makeReceipt({
    tags: [["p", OPERATOR_HEX], ["P", PAYER_HEX], ["amount", "4999999"], ["bolt11", "lnbcinvoice"]]
  })), null);
  assert.equal(await verify(makeReceipt({
    tags: [["p", OPERATOR_HEX], ["P", PAYER_HEX], ["amount", "5000000msat"], ["bolt11", "lnbcinvoice"]]
  })), null);
  assert.equal(await verify(makeReceipt({
    tags: [["p", OPERATOR_HEX], ["P", PAYER_HEX], ["amount", "5000000"]]
  })), null);
});

test("rejects stale and excessively future-dated zap receipts", async () => {
  const now = Math.floor(Date.now() / 1000);
  assert.equal(await verify(makeReceipt({ created_at: now - 31 * 24 * 3600 })), null);
  assert.equal(await verify(makeReceipt({ created_at: now + 16 * 60 })), null);
});
