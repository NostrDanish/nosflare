import { NostrEvent } from './types';

// Zap receipt (NIP-57 kind 9735) verification for pay-to-relay.
// A payment is recorded only from a structurally and cryptographically valid
// zap receipt issued by the operator's LNURL server after invoice settlement:
//   - kind 9735 with a valid Schnorr signature;
//   - `p` tag = the relay operator's pubkey (relayNpub);
//   - `P` tag = the payer (this pubkey receives access);
//   - `bolt11` tag present (the paid invoice) and `amount` (msats) >= price;
//   - receipt not absurdly old (replay hygiene).
const MAX_RECEIPT_AGE_SECONDS = 30 * 24 * 3600; // 30 days

export interface VerifiedPayment {
  payer: string;      // payer pubkey (zap sender, `P` tag) that gets relay access
  amountSats: number; // paid amount in sats
  receiptId: string;  // zap receipt event id (audit trail)
  bolt11: string;     // the paid invoice (audit trail)
}

export async function verifyZapReceipt(
  event: NostrEvent,
  operatorNpub: string,
  priceSats: number,
  verifyEvent: (event: NostrEvent) => Promise<boolean>
): Promise<VerifiedPayment | null> {
  try {
    if (!event || event.kind !== 9735) return null;

    const operatorHex = npubToHex(operatorNpub);
    if (!operatorHex) {
      console.error("Configured relayNpub is not a valid npub");
      return null;
    }

    const tags = event.tags ?? [];
    const tag = (name: string) => tags.find((t) => t[0] === name && t[1])?.[1];

    // Recipient must be the relay operator; sender (P) is the payer.
    if (tag("p") !== operatorHex) return null;
    const payer = tag("P");
    if (!payer || !/^[0-9a-f]{64}$/.test(payer)) return null;

    // Amount (msats) must cover the configured price.
    const amountTag = tag("amount");
    const amountMsats = amountTag ? Number.parseInt(amountTag, 10) : NaN;
    if (!Number.isFinite(amountMsats) || amountMsats < priceSats * 1000) return null;

    // The paid invoice must be attached.
    const bolt11 = tag("bolt11");
    if (!bolt11 || !bolt11.toLowerCase().startsWith("ln")) return null;

    // Receipt freshness.
    const now = Math.floor(Date.now() / 1000);
    if (event.created_at > now + 900 || event.created_at < now - MAX_RECEIPT_AGE_SECONDS) return null;

    if (!(await verifyEvent(event))) return null;

    return {
      payer,
      amountSats: Math.floor(amountMsats / 1000),
      receiptId: event.id,
      bolt11,
    };
  } catch (error) {
    console.error("Zap receipt verification failed:", error);
    return null;
  }
}

// Minimal bech32 (BIP-173) decode for `npub` -> hex pubkey. Only what the
// payment path needs: parse the operator's configured npub to the 32-byte hex
// pubkey compared against zap receipt `p` tags.
const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

function bech32Polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((top >> i) & 1) chk ^= GEN[i];
    }
  }
  return chk;
}

function bech32HrpExpand(hrp: string): number[] {
  return [...hrp].map((c) => c.charCodeAt(0) >> 5)
    .concat([0], [...hrp].map((c) => c.charCodeAt(0) & 31));
}

function bech32ConvertBits(data: number[], fromBits: number, toBits: number, pad: boolean): number[] | null {
  let acc = 0;
  let bits = 0;
  const ret: number[] = [];
  const maxv = (1 << toBits) - 1;
  for (const value of data) {
    if (value < 0 || value >> fromBits !== 0) return null;
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) ret.push((acc << (toBits - bits)) & maxv);
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) !== 0) {
    return null;
  }
  return ret;
}

// Decode a NIP-19 npub to a lowercase hex pubkey. Returns null for anything
// malformed or not an npub.
export function npubToHex(npub: string): string | null {
  try {
    const value = String(npub).trim().toLowerCase();
    const split = value.lastIndexOf("1");
    if (split < 1 || split + 7 > value.length) return null;
    const hrp = value.slice(0, split);
    if (hrp !== "npub") return null;

    const data: number[] = [];
    for (const c of value.slice(split + 1)) {
      const d = BECH32_CHARSET.indexOf(c);
      if (d === -1) return null;
      data.push(d);
    }
    if (data.length < 6) return null;
    if (bech32Polymod(bech32HrpExpand(hrp).concat(data)) !== 1) return null;

    const words = bech32ConvertBits(data.slice(0, -6), 5, 8, false);
    if (!words || words.length !== 32) return null;

    return words.map((b) => b.toString(16).padStart(2, "0")).join("");
  } catch {
    return null;
  }
}
