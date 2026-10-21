import { NostrEvent } from './types';

// Zap receipt (NIP-57 kind 9735) verification for pay-to-relay.
// A payment is recorded only from a structurally and cryptographically valid
// zap receipt issued by the operator's LNURL server after invoice settlement:
//   - kind 9735 with a valid Schnorr signature;
//   - receipt signer (event.pubkey) = the operator's LNURL server nostr key,
//     configured directly (LNURL_SERVER_PUBKEY) or resolved from the payee's
//     lud16 LNURL endpoint (`nostrPubkey`); this rejects self-signed forgeries;
//   - `p` tag = the relay operator's pubkey (relayNpub);
//   - `P` tag = the payer (this pubkey receives access);
//   - `bolt11` tag present (the paid invoice) and `amount` (msats) >= price;
//   - receipt not absurdly old (replay hygiene).
const MAX_RECEIPT_AGE_SECONDS = 30 * 24 * 3600; // 30 days
const LNURL_PUBKEY_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

// Module-level cache for lud16-resolved LNURL server pubkeys, keyed by lud16.
const lnurlPubkeyCache = new Map<string, { key: string; expiresAt: number }>();

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
  verifyEvent: (event: NostrEvent) => Promise<boolean>,
  lnurlServerPubkey?: string,
  payeeLud16?: string
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

    // Receipt-issuer binding (the NIP-57 check): the receipt must be signed by
    // the operator's LNURL server's nostr key. A Schnorr-valid receipt signed
    // by any other key (e.g. a self-signed forgery) is rejected here. Resolved
    // after signature verification so garbage events can't trigger lookups.
    const issuerKey = await resolveLnurlServerPubkey(lnurlServerPubkey, payeeLud16);
    if (!issuerKey || event.pubkey !== issuerKey) return null;

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

// Resolve the nostr signing key of the operator's LNURL server. Prefers a
// directly configured hex pubkey (no network dependency); otherwise fetches
// the payee lud16's LNURL-pay endpoint and reads `nostrPubkey` per NIP-57.
// Resolved keys are cached for LNURL_PUBKEY_CACHE_TTL_MS. Fails closed: any
// missing config, fetch error (retried once), or malformed response returns
// null, which causes receipt rejection.
export async function resolveLnurlServerPubkey(
  directPubkey?: string,
  payeeLud16?: string
): Promise<string | null> {
  try {
    const direct = String(directPubkey ?? "").trim().toLowerCase();
    if (/^[0-9a-f]{64}$/.test(direct)) return direct;

    const lud16 = String(payeeLud16 ?? "").trim().toLowerCase();
    const match = /^([a-z0-9._+-]+)@([a-z0-9.-]+\.[a-z]{2,})$/.exec(lud16);
    if (!match) return null;
    const [, name, domain] = match;

    const now = Date.now();
    const cached = lnurlPubkeyCache.get(lud16);
    if (cached && cached.expiresAt > now) {
      return cached.key;
    }

    const url = `https://${domain}/.well-known/lnurlp/${name}`;
    let data: any = null;
    for (let attempt = 0; attempt < 2; attempt++) { // retry transport errors once
      try {
        const response = await fetch(url, { headers: { Accept: "application/json" } });
        if (!response.ok) return null;
        data = await response.json();
        break;
      } catch {
        if (attempt === 1) return null;
      }
    }
    if (!data || data.allowsNostr !== true) return null;
    const nostrPubkey = String(data.nostrPubkey ?? "").trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(nostrPubkey)) return null;

    lnurlPubkeyCache.set(lud16, { key: nostrPubkey, expiresAt: now + LNURL_PUBKEY_CACHE_TTL_MS });
    return nostrPubkey;
  } catch (error) {
    console.error("LNURL server pubkey resolution failed:", error);
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
