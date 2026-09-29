/**
 * Configuration - Change optional relay settings
 */

// ***************************** //
// ** BEGIN EDITABLE SETTINGS ** //
// ***************************** //

// Settings below can be configured to your preferences

// Pay to relay
export const relayNpub = "npub1c3gyzcvf2xakqy4vy06umu7hgpr97ttyp05yrlvmk8g8xvmse57qj286r6"; // 0xPrivacy
export const PAY_TO_RELAY_ENABLED = true; // Set to false to disable pay to relay
export const RELAY_ACCESS_PRICE_SATS = 5000; // Price in SATS for relay access

// Relay info
export const relayInfo: RelayInfo = {
  name: "0xServerless",
  description: "just getting started.\n\nBreaking the digital cage, one guide at a time.  \n#Monero • #TOR • #Nostr • #IPFS #mirrors\n\nhttps://linkfork.io/0xprivacy",
  pubkey: "c45041618951bb6012ac23f5cdf3d740465f2d640be841fd9bb1d0733370cd3c",
  contact: "0xPrivacy@tmail.ae",
  supported_nips: [1, 2, 4, 5, 9, 11, 12, 15, 16, 17, 20, 22, 23, 33, 40, 42, 50, 51, 58, 65, 71, 78, 89, 94],
  software: "https://github.com/Spl0itable/nosflare",
  version: "8.9.26",
  icon: "https://i.postimg.cc/zBBG2Nc9/photo-2026-04-14-04-39-04.jpg",
  banner: "https://i.postimg.cc/cCv6CW7S/photo-2026-04-14-04-38-19.jpg",

  // Relay limitations
  limitation: {
    max_message_length: 1048576, // 1MB (Cloudflare WS hard cap)
    max_subscriptions: 500,
    max_limit: 10000,
    max_subid_length: 256,
    max_event_tags: 5000,
    max_content_length: 70000,
    // min_pow_difficulty: 0,
    auth_required: false, // Set to true to enable NIP-42 authentication
    payment_required: PAY_TO_RELAY_ENABLED,
    restricted_writes: PAY_TO_RELAY_ENABLED,
    created_at_lower_limit: 946684800, // January 1, 2000
    created_at_upper_limit: 2147483647, // Max unix timestamp (year 2038)
    // default_limit: 10000
  },
};

// Nostr address NIP-05 verified users (for verified checkmark like username@your-relay.com)
export const nip05Users: Record<string, string> = {
  "0xPrivacy": "c45041618951bb6012ac23f5cdf3d740465f2d640be841fd9bb1d0733370cd3c",
  // ... more NIP-05 verified users
};

// Blocked pubkeys
export const blockedPubkeys = new Set([
  "3c7f5948b5d80900046a67d8e3bf4971d6cba013abece1dd542eca223cf3dd3f",
  "fed5c0c3c8fe8f51629a0b39951acdf040fd40f53a327ae79ee69991176ba058",
  "e810fafa1e89cdf80cced8e013938e87e21b699b24c8570537be92aec4b12c18",
  "05aee96dd41429a3ae97a9dac4dfc6867fdfacebca3f3bdc051e5004b0751f01",
  "53a756bb596055219d93e888f71d936ec6c47d960320476c955efd8941af4362"
]);

// Allowed pubkeys (empty = allowlist off; blockedPubkeys still apply)
export const allowedPubkeys = new Set<string>([]);

// Blocked event kinds
export const blockedEventKinds = new Set([
  1064
]);

// Allowed event kinds (empty = all allowed)
export const allowedEventKinds = new Set<number>([]);

// Blocked words or phrases (case-insensitive)
export const blockedContent = new Set([
  "~~ hello world! ~~"
]);

// NIP-05 validation
export const checkValidNip05 = false;

// Blocked NIP-05 domains
export const blockedNip05Domains = new Set<string>([]);

// Allowed NIP-05 domains
export const allowedNip05Domains = new Set<string>([]);

// Blocked tags
export const blockedTags = new Set<string>([]);

// Allowed tags
export const allowedTags = new Set<string>([]);

// ConnectionDO sharding: each WebSocket connection gets its own hibernating DO
export const CONNECTION_DO_SHARDING_ENABLED = true;

// SessionManagerDO sharding (small relay: fewer shards = fewer DO requests)
export const SESSION_MANAGER_SHARD_COUNT = 5;

// EventShardDO time windows per REQ
export const MAX_TIME_WINDOWS_PER_QUERY = 30;

// EventShardDO read replicas (small relay: 2 suffice)
export const READ_REPLICAS_PER_SHARD = 2;

// PaymentDO sharding
export const PAYMENT_DO_SHARDING_ENABLED = true;

// Rate limit thresholds (sync-friendly)
export const PUBKEY_RATE_LIMIT = { rate: 600 / 60000, capacity: 600 }; // 600 EVENT messages per min
export const REQ_RATE_LIMIT = { rate: 300 / 60000, capacity: 300 }; // 300 REQ messages per min
export const excludedRateLimitKinds = new Set<number>([
  1059
]);

// *************************** //
// ** END EDITABLE SETTINGS ** //
// *************************** //

import { RelayInfo } from './types';
import { NostrEvent } from './types';

export const CREATED_AT_LOWER_LIMIT = relayInfo.limitation?.created_at_lower_limit ?? 0;
export const CREATED_AT_UPPER_LIMIT = relayInfo.limitation?.created_at_upper_limit ?? 2147483647;
export const AUTH_REQUIRED = relayInfo.limitation?.auth_required ?? false;

export function isPubkeyAllowed(pubkey: string): boolean {
  if (allowedPubkeys.size > 0 && !allowedPubkeys.has(pubkey)) {
    return false;
  }
  return !blockedPubkeys.has(pubkey);
}

export function isEventKindAllowed(kind: number): boolean {
  if (allowedEventKinds.size > 0 && !allowedEventKinds.has(kind)) {
    return false;
  }
  return !blockedEventKinds.has(kind);
}

export function containsBlockedContent(event: NostrEvent): boolean {
  const lowercaseContent = (event.content || "").toLowerCase();
  const lowercaseTags = event.tags.map(tag => tag.join("").toLowerCase());

  for (const blocked of blockedContent) {
    const blockedLower = blocked.toLowerCase();
    if (
      lowercaseContent.includes(blockedLower) ||
      lowercaseTags.some(tag => tag.includes(blockedLower))
    ) {
      return true;
    }
  }
  return false;
}

export function isTagAllowed(tag: string): boolean {
  if (allowedTags.size > 0 && !allowedTags.has(tag)) {
    return false;
  }
  return !blockedTags.has(tag);
}