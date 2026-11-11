/** Nostr replaceable-event coordinate and ordering helpers. Kept pure for unit testing. */

export interface AddressableCoordinate {
  kind: number;
  pubkey: string;
  dTag: string;
}

export function isReplaceableKind(kind: number): boolean {
  return kind === 0 || kind === 3 || (kind >= 10000 && kind < 20000);
}

/** True for replaceable kinds whose address includes a d-tag. */
export function isParameterizedReplaceableKind(kind: number): boolean {
  return kind >= 30000 && kind < 40000;
}

/**
 * NIP-01 replaceable-event ordering: newer created_at wins; when timestamps
 * tie, the lexicographically lower event id wins.
 */
export function isIncomingReplaceableWinner(
  incomingCreatedAt: number,
  incomingId: string,
  existingCreatedAt: number,
  existingId: string,
): boolean {
  return incomingCreatedAt > existingCreatedAt ||
    (incomingCreatedAt === existingCreatedAt && incomingId < existingId);
}

/**
 * Parse a NIP-09/NIP-01 address coordinate and ensure it targets the deleting
 * author's own replaceable event. The d-tag may contain colons, so only the
 * first two separators are structural.
 */
export function parseAddressableCoordinate(
  value: string,
  deletingPubkey: string,
): AddressableCoordinate | null {
  const first = value.indexOf(":");
  const second = first < 0 ? -1 : value.indexOf(":", first + 1);
  if (first <= 0 || second < 0) return null;

  const kindText = value.slice(0, first);
  const pubkey = value.slice(first + 1, second);
  const dTag = value.slice(second + 1);
  if (!/^\d+$/.test(kindText) || !/^[0-9a-f]{64}$/.test(pubkey)) return null;

  const kind = Number(kindText);
  if (!Number.isSafeInteger(kind) || kind < 0 || kind > 65535) return null;
  if (pubkey !== deletingPubkey) return null;
  if (!isReplaceableKind(kind) && !isParameterizedReplaceableKind(kind)) return null;
  if (isReplaceableKind(kind) && dTag !== "") return null;

  return { kind, pubkey, dTag };
}
