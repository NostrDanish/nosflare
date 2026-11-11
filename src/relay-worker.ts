import { schnorr } from "@noble/curves/secp256k1.js";
import { Env, NostrEvent, NostrFilter, QueryResult, NostrMessage, Nip05Response } from './types';
import * as config from './config';
import { RelayWebSocket } from './durable-object';
import { verifyZapReceipt } from './zap-verification';
import { serveLandingPage } from './landing-page';
import { CHUNK_SIZE, buildCountQuery, buildQuery, queryDatabaseChunked } from './query-builder';
import { initializeDatabase, getDatabaseSizeBytes, pruneOldEvents } from './db-maintenance';

// Import config values
const {
  relayInfo,
  PAY_TO_RELAY_ENABLED,
  RELAY_ACCESS_PRICE_SATS,
  relayNpub,
  LNURL_SERVER_PUBKEY,
  PAYEE_LUD16,
  nip05Users,
  enableAntiSpam,
  enableGlobalDuplicateCheck,
  antiSpamKinds,
  checkValidNip05,
  blockedNip05Domains,
  allowedNip05Domains,
  DB_PRUNING_ENABLED,
  DB_SIZE_THRESHOLD_GB,
  DB_PRUNE_BATCH_SIZE,
  DB_PRUNE_TARGET_GB,
  pruneProtectedKinds,
} = config;

// Query optimization constants
const GLOBAL_MAX_EVENTS = 500;
const MAX_QUERY_COMPLEXITY = 1000;

// Event verification
async function verifyEventSignature(event: NostrEvent): Promise<boolean> {
  try {
    const signatureBytes = hexToBytes(event.sig);
    const serializedEventData = serializeEventForSigning(event);
    const messageHashBuffer = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(serializedEventData)
    );
    const messageHash = new Uint8Array(messageHashBuffer);
    const publicKeyBytes = hexToBytes(event.pubkey);
    return schnorr.verify(signatureBytes, messageHash, publicKeyBytes);
  } catch (error) {
    console.error("Error verifying event signature:", error);
    return false;
  }
}

function serializeEventForSigning(event: NostrEvent): string {
  return JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  ]);
}

function hexToBytes(hexString: string): Uint8Array {
  if (hexString.length % 2 !== 0) throw new Error("Invalid hex string");
  const bytes = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hexString.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(byte => byte.toString(16).padStart(2, '0')).join('');
}

// Content hashing for anti-spam
async function hashContent(event: NostrEvent): Promise<string> {
  const contentToHash = enableGlobalDuplicateCheck
    ? JSON.stringify({ kind: event.kind, tags: event.tags, content: event.content })
    : JSON.stringify({ pubkey: event.pubkey, kind: event.kind, tags: event.tags, content: event.content });

  const buffer = new TextEncoder().encode(contentToHash);
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  return bytesToHex(new Uint8Array(hashBuffer));
}

function shouldCheckForDuplicates(kind: number): boolean {
  return enableAntiSpam && antiSpamKinds.has(kind);
}

// Payment handling
async function hasPaidForRelay(pubkey: string, env: Env): Promise<boolean | null> {
  if (!PAY_TO_RELAY_ENABLED) return true;

  try {
    const session = env.RELAY_DATABASE.withSession('first-unconstrained');
    const result = await session.prepare(
      "SELECT pubkey FROM paid_pubkeys WHERE pubkey = ? LIMIT 1"
    ).bind(pubkey).first();
    return result !== null;
  } catch (error) {
    console.error(`Error checking paid status for ${pubkey}:`, error);
    return null; // null = unknown (DB error), don't cache this
  }
}

async function savePaidPubkey(pubkey: string, env: Env, amountSats: number = RELAY_ACCESS_PRICE_SATS): Promise<boolean> {
  try {
    const session = env.RELAY_DATABASE.withSession('first-primary');
    await session.prepare(`
      INSERT INTO paid_pubkeys (pubkey, paid_at, amount_sats)
      VALUES (?, ?, ?)
      ON CONFLICT(pubkey) DO UPDATE SET
        paid_at = excluded.paid_at,
        amount_sats = excluded.amount_sats
    `).bind(pubkey, Math.floor(Date.now() / 1000), amountSats).run();
    return true;
  } catch (error) {
    console.error(`Error saving paid pubkey ${pubkey}:`, error);
    return false;
  }
}

// Fetches kind 0 event from fallback relay
function fetchEventFromFallbackRelay(pubkey: string): Promise<NostrEvent | null> {
  return new Promise((resolve, reject) => {
    const fallbackRelayUrl = 'wss://relay.primal.net';
    const ws = new WebSocket(fallbackRelayUrl);
    let hasClosed = false;

    const closeWebSocket = (subscriptionId: string | null) => {
      if (!hasClosed && ws.readyState === WebSocket.OPEN) {
        if (subscriptionId) {
          ws.send(JSON.stringify(["CLOSE", subscriptionId]));
        }
        ws.close();
        hasClosed = true;
        console.log('WebSocket connection to fallback relay closed');
      }
    };

    ws.addEventListener('open', () => {
      console.log("WebSocket connection to fallback relay opened.");
      const subscriptionId = Math.random().toString(36).substr(2, 9);
      const filters = {
        kinds: [0],
        authors: [pubkey],
        limit: 1
      };
      const reqMessage = JSON.stringify(["REQ", subscriptionId, filters]);
      ws.send(reqMessage);
    });

    ws.addEventListener('message', event => {
      try {
        // @ts-ignore - Cloudflare Workers WebSocket event has data property
        const message = JSON.parse(event.data) as NostrMessage;

        // Handle EVENT message
        if (message[0] === "EVENT" && message[1]) {
          const eventData = message[2];
          if (eventData.kind === 0 && eventData.pubkey === pubkey) {
            console.log("Received kind 0 event from fallback relay.");
            closeWebSocket(message[1]);
            resolve(eventData);
          }
        }

        // Handle EOSE message
        else if (message[0] === "EOSE") {
          console.log("EOSE received from fallback relay, no kind 0 event found.");
          closeWebSocket(message[1]);
          resolve(null);
        }
      } catch (error) {
        console.error(`Error processing fallback relay event for pubkey ${pubkey}: ${error}`);
        reject(error);
      }
    });

    ws.addEventListener('error', (error: Event) => {
      console.error(`WebSocket error with fallback relay:`, error);
      ws.close();
      hasClosed = true;
      reject(error);
    });

    ws.addEventListener('close', () => {
      hasClosed = true;
      console.log('Fallback relay WebSocket connection closed.');
    });

    setTimeout(() => {
      if (!hasClosed) {
        console.log('Timeout reached. Closing WebSocket connection to fallback relay.');
        closeWebSocket(null);
        reject(new Error(`No response from fallback relay for pubkey ${pubkey}`));
      }
    }, 5000);
  });
}

// Fetch kind 0 event for pubkey
async function fetchKind0EventForPubkey(pubkey: string, env: Env): Promise<NostrEvent | null> {
  try {
    const filters = [{ kinds: [0], authors: [pubkey], limit: 1 }];
    const result = await queryEvents(filters, 'first-unconstrained', env);

    if (result.events && result.events.length > 0) {
      return result.events[0];
    }

    // If no event found from local database, use fallback relay
    console.log(`No kind 0 event found locally, trying fallback relay: wss://relay.primal.net`);
    const fallbackEvent = await fetchEventFromFallbackRelay(pubkey);
    if (fallbackEvent) {
      return fallbackEvent;
    }
  } catch (error) {
    console.error(`Error fetching kind 0 event for pubkey ${pubkey}: ${error}`);
  }

  return null;
}

// NIP-05 validation
async function validateNIP05FromKind0(pubkey: string, env: Env): Promise<boolean> {
  try {
    // Fetch kind 0 event for the pubkey
    const metadataEvent = await fetchKind0EventForPubkey(pubkey, env);

    if (!metadataEvent) {
      console.error(`No kind 0 metadata event found for pubkey: ${pubkey}`);
      return false;
    }

    const metadata = JSON.parse(metadataEvent.content);
    const nip05Address = metadata.nip05;

    if (!nip05Address) {
      console.error(`No NIP-05 address found in kind 0 for pubkey: ${pubkey}`);
      return false;
    }

    // Validate the NIP-05 address
    const isValid = await validateNIP05(nip05Address, pubkey);
    return isValid;

  } catch (error) {
    console.error(`Error validating NIP-05 for pubkey ${pubkey}: ${error}`);
    return false;
  }
}

async function validateNIP05(nip05Address: string, pubkey: string): Promise<boolean> {
  try {
    const [name, domain] = nip05Address.split('@');

    if (!domain) {
      throw new Error(`Invalid NIP-05 address format: ${nip05Address}`);
    }

    // Check blocked/allowed domains
    if (blockedNip05Domains.has(domain)) {
      console.error(`NIP-05 domain is blocked: ${domain}`);
      return false;
    }

    if (allowedNip05Domains.size > 0 && !allowedNip05Domains.has(domain)) {
      console.error(`NIP-05 domain is not allowed: ${domain}`);
      return false;
    }

    // Fetch the NIP-05 data
    const url = `https://${domain}/.well-known/nostr.json?name=${name}`;
    const response = await fetch(url);

    if (!response.ok) {
      console.error(`Failed to fetch NIP-05 data from ${url}: ${response.statusText}`);
      return false;
    }

    const nip05Data = await response.json() as Nip05Response;

    if (!nip05Data.names || !nip05Data.names[name]) {
      console.error(`NIP-05 data does not contain a matching public key for ${name}`);
      return false;
    }

    const nip05Pubkey = nip05Data.names[name];
    return nip05Pubkey === pubkey;

  } catch (error) {
    console.error(`Error validating NIP-05 address: ${error}`);
    return false;
  }
}

// Query complexity calculation
function calculateQueryComplexity(filter: NostrFilter): number {
  let complexity = 0;

  // Base complexity
  complexity += (filter.ids?.length || 0) * 1;
  complexity += (filter.authors?.length || 0) * 2;
  complexity += (filter.kinds?.length || 0) * 5;

  // Tag filters are expensive
  for (const [key, values] of Object.entries(filter)) {
    if (key.startsWith('#') && Array.isArray(values)) {
      complexity += values.length * 10;
    }
  }

  // No time bounds is very expensive
  if (!filter.since && !filter.until) {
    complexity *= 2;
  }

  // Large limits are expensive
  if ((filter.limit || 0) > 1000) {
    complexity *= 1.5;
  }

  return complexity;
}

// Event processing
async function processEvent(event: NostrEvent, sessionId: string, env: Env): Promise<{ success: boolean; message: string; bookmark?: string }> {
  try {
    // NIP-05 validation if enabled (bypassed for kind 1059)
    if (event.kind !== 1059 && checkValidNip05 && event.kind !== 0) {
      const isValidNIP05 = await validateNIP05FromKind0(event.pubkey, env);
      if (!isValidNIP05) {
        console.error(`Event denied. NIP-05 validation failed for pubkey ${event.pubkey}.`);
        return { success: false, message: "invalid: NIP-05 validation failed" };
      }
    }

    // Handle deletion events
    if (event.kind === 5) {
      return await processDeletionEvent(event, env);
    }

    // NIP-16: Ephemeral events (kinds 20000-29999) are broadcast but never stored
    if (event.kind >= 20000 && event.kind < 30000) {
      return { success: true, message: "Ephemeral event broadcast" };
    }

    // Save event directly to database (duplicate check happens inside saveEventToDatabase)
    return await saveEventToDatabase(event, env);

  } catch (error: any) {
    console.error(`Error processing event: ${error.message}`);
    return { success: false, message: `error: ${error.message}` };
  }
}

// Save event directly to D1 database
async function saveEventToDatabase(event: NostrEvent, env: Env): Promise<{ success: boolean; message: string; bookmark?: string }> {
  try {
    // Check worker cache for duplicate event ID
    const cache = caches.default;
    const cacheKey = new Request(`https://event-cache/${event.id}`);
    const cached = await cache.match(cacheKey);
    if (cached) {
      return { success: false, message: "duplicate: event already exists" };
    }

    const session = env.RELAY_DATABASE.withSession('first-primary');

    // Check D1 for duplicate event ID
    const existingEvent = await session.prepare("SELECT id FROM events WHERE id = ? LIMIT 1").bind(event.id).first();
    if (existingEvent) {
      return { success: false, message: "duplicate: event already exists", bookmark: session.getBookmark() ?? undefined };
    }

    // NIP-16: Replaceable events (kinds 0, 3, 10000-19999)
    // Only the latest event (by created_at) for a given (kind, pubkey) should be stored
    const isReplaceable = event.kind === 0 || event.kind === 3 || (event.kind >= 10000 && event.kind < 20000);
    if (isReplaceable) {
      const existing = await session.prepare(
        "SELECT id, created_at FROM events WHERE kind = ? AND pubkey = ? LIMIT 1"
      ).bind(event.kind, event.pubkey).first();

      if (existing) {
        if (event.created_at <= (existing.created_at as number)) {
          return { success: false, message: "duplicate: a newer or equal replaceable event already exists", bookmark: session.getBookmark() ?? undefined };
        }
        // Delete the older event and its associated data
        const oldId = existing.id as string;
        await session.batch([
          session.prepare("DELETE FROM tags WHERE event_id = ?").bind(oldId),
          session.prepare("DELETE FROM content_hashes WHERE event_id = ?").bind(oldId),
          session.prepare("DELETE FROM event_tags_cache_multi WHERE event_id = ?").bind(oldId),
          session.prepare("DELETE FROM events WHERE id = ?").bind(oldId),
        ]);
        console.log(`Replaced older event ${oldId} with newer event ${event.id} (kind ${event.kind})`);
      }
    }

    // NIP-33: Parameterized replaceable events (kinds 30000-39999)
    // Only the latest event for a given (kind, pubkey, d-tag) should be stored
    const isParameterizedReplaceable = event.kind >= 30000 && event.kind < 40000;
    if (isParameterizedReplaceable) {
      const dTag = event.tags.find(t => t[0] === 'd')?.[1] || '';
      const existing = await session.prepare(
        "SELECT id, created_at FROM events WHERE kind = ? AND pubkey = ? AND tag_d = ? LIMIT 1"
      ).bind(event.kind, event.pubkey, dTag).first();

      if (existing) {
        if (event.created_at <= (existing.created_at as number)) {
          return { success: false, message: "duplicate: a newer or equal parameterized replaceable event already exists", bookmark: session.getBookmark() ?? undefined };
        }
        // Delete the older event and its associated data
        const oldId = existing.id as string;
        await session.batch([
          session.prepare("DELETE FROM tags WHERE event_id = ?").bind(oldId),
          session.prepare("DELETE FROM content_hashes WHERE event_id = ?").bind(oldId),
          session.prepare("DELETE FROM event_tags_cache_multi WHERE event_id = ?").bind(oldId),
          session.prepare("DELETE FROM events WHERE id = ?").bind(oldId),
        ]);
        console.log(`Replaced older parameterized event ${oldId} with newer event ${event.id} (kind ${event.kind}, d=${dTag})`);
      }
    }

    // Check for duplicate content (only if anti-spam is enabled)
    let contentHash: string | null = null;
    if (shouldCheckForDuplicates(event.kind)) {
      contentHash = await hashContent(event);

      // Check D1 for existing content hash
      const duplicateContent = enableGlobalDuplicateCheck
        ? await session.prepare("SELECT event_id FROM content_hashes WHERE hash = ? LIMIT 1").bind(contentHash).first()
        : await session.prepare("SELECT event_id FROM content_hashes WHERE hash = ? AND pubkey = ? LIMIT 1").bind(contentHash, event.pubkey).first();

      if (duplicateContent) {
        return { success: false, message: "duplicate: content already exists", bookmark: session.getBookmark() ?? undefined };
      }
    }

    // Process tags and extract common tag values
    const tagInserts: Array<{ name: string; value: string }> = [];
    let tagP: string | null = null;
    let tagE: string | null = null;
    let tagA: string | null = null;
    let tagT: string | null = null;
    let tagD: string | null = null;
    let tagR: string | null = null;
    let tagL: string | null = null;
    let tagS: string | null = null;
    let tagU: string | null = null;

    for (const tag of event.tags) {
      if (tag[0]) {
        tagInserts.push({
          name: tag[0],
          value: tag[1] || ''
        });

        // Capture first occurrence of common tags
        if (tag[0] === 'p' && !tagP) tagP = tag[1];
        if (tag[0] === 'e' && !tagE) tagE = tag[1];
        if (tag[0] === 'a' && !tagA) tagA = tag[1];
        if (tag[0] === 't' && !tagT) tagT = tag[1];
        if (tag[0] === 'd' && !tagD) tagD = tag[1];
        if (tag[0] === 'r' && !tagR) tagR = tag[1];
        if (tag[0] === 'L' && !tagL) tagL = tag[1];
        if (tag[0] === 's' && !tagS) tagS = tag[1];
        if (tag[0] === 'u' && !tagU) tagU = tag[1];
      }
    }

    // Extract thread metadata
    const eTags = tagInserts.filter(t => t.name === 'e').map(t => t.value);
    const replyToEventId = eTags.length > 0 ? eTags[0] : null;
    const rootEventId = eTags.length > 1 ? eTags[eTags.length - 1] : null;
    const contentPreview = event.content.substring(0, 100);

    // Insert the main event
    const insertResult = await session.prepare(`
      INSERT INTO events (id, pubkey, created_at, kind, tags, content, sig, tag_p, tag_e, tag_a, tag_t, tag_d, tag_r, tag_L, tag_s, tag_u, reply_to_event_id, root_event_id, content_preview)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO NOTHING
    `).bind(
      event.id,
      event.pubkey,
      event.created_at,
      event.kind,
      JSON.stringify(event.tags),
      event.content,
      event.sig,
      tagP,
      tagE,
      tagA,
      tagT,
      tagD,
      tagR,
      tagL,
      tagS,
      tagU,
      replyToEventId,
      rootEventId,
      contentPreview
    ).run();

    // Check if the event was actually inserted (not a duplicate that slipped through)
    if (insertResult.meta.changes === 0) {
      console.log(`Event ${event.id} already exists in database (race condition duplicate)`);
      return { success: false, message: "duplicate: event already exists", bookmark: session.getBookmark() ?? undefined };
    }

    // Consolidate all post-insert writes (tags, caches, content hash) into a single batch
    // to minimize D1 round-trips to the primary
    const postInsertBatch: ReturnType<typeof session.prepare>[] = [];

    // Tag inserts
    for (const t of tagInserts) {
      postInsertBatch.push(
        session.prepare('INSERT INTO tags (event_id, tag_name, tag_value) VALUES (?, ?, ?)').bind(event.id, t.name, t.value)
      );
    }

    // Multi-value tag cache for p/e/a/t/d/r/L/s/u tags
    const cacheableTags = tagInserts.filter(t => ['p', 'e', 'a', 't', 'd', 'r', 'L', 's', 'u'].includes(t.name));
    for (const t of cacheableTags) {
      postInsertBatch.push(
        session.prepare(`
          INSERT OR IGNORE INTO event_tags_cache_multi (event_id, pubkey, kind, created_at, tag_type, tag_value)
          VALUES (?, ?, ?, ?, ?, ?)
        `).bind(event.id, event.pubkey, event.kind, event.created_at, t.name, t.value)
      );
    }

    // Content hash
    if (contentHash) {
      postInsertBatch.push(
        session.prepare(`
          INSERT INTO content_hashes (hash, event_id, pubkey, created_at)
          VALUES (?, ?, ?, ?)
          ON CONFLICT(hash) DO NOTHING
        `).bind(contentHash, event.id, event.pubkey, event.created_at)
      );
    }

    // Execute all post-insert writes in chunks of 100 (D1 batch limit)
    for (let i = 0; i < postInsertBatch.length; i += 100) {
      await session.batch(postInsertBatch.slice(i, i + 100));
    }

    // Cache the event ID in worker cache to prevent duplicates
    await cache.put(cacheKey, new Response('cached', {
      headers: {
        'Cache-Control': 'max-age=3600'
      }
    }));

    console.log(`Event ${event.id} saved directly to database`);
    return { success: true, message: "Event saved successfully", bookmark: session.getBookmark() ?? undefined };

  } catch (error: any) {
    console.error(`Error saving event to database: ${error.message}`);
    console.error(`Event details: ID=${event.id}, Kind=${event.kind}, Tags count=${event.tags.length}`);
    return { success: false, message: `error: ${error.message}` };
  }
}

// Helper function for kind 5
async function processDeletionEvent(event: NostrEvent, env: Env): Promise<{ success: boolean; message: string; bookmark?: string }> {
  console.log(`Processing deletion event ${event.id}`);
  const deletedEventIds = event.tags.filter(tag => tag[0] === "e").map(tag => tag[1]);

  const session = env.RELAY_DATABASE.withSession('first-primary');

  if (deletedEventIds.length === 0) {
    return { success: true, message: "No events to delete", bookmark: session.getBookmark() ?? undefined };
  }

  let deletedCount = 0;
  const errors: string[] = [];
  const idsToDelete: string[] = [];

  // Verify ownership for all events in a single query
  if (deletedEventIds.length > 0) {
    try {
      const ownerPlaceholders = deletedEventIds.map(() => '?').join(',');
      const ownerResult = await session.prepare(
        `SELECT id, pubkey FROM events WHERE id IN (${ownerPlaceholders})`
      ).bind(...deletedEventIds).all();

      const eventOwners = new Map<string, string>();
      for (const row of ownerResult.results) {
        eventOwners.set(row.id as string, row.pubkey as string);
      }

      for (const eventId of deletedEventIds) {
        const ownerPubkey = eventOwners.get(eventId);
        if (!ownerPubkey) {
          console.warn(`Event ${eventId} not found in D1. Nothing to delete (may be in queue).`);
          continue;
        }
        if (ownerPubkey !== event.pubkey) {
          console.warn(`Event ${eventId} does not belong to pubkey ${event.pubkey}. Skipping deletion.`);
          errors.push(`unauthorized: cannot delete event ${eventId} - wrong pubkey`);
          continue;
        }
        idsToDelete.push(eventId);
      }
    } catch (error) {
      console.error('Error checking event ownership:', error);
      errors.push('error checking event ownership');
    }
  }

  // Second pass: batch delete all verified events in one D1 call
  if (idsToDelete.length > 0) {
    try {
      const deleteStatements: ReturnType<typeof session.prepare>[] = [];
      for (const eventId of idsToDelete) {
        deleteStatements.push(
          session.prepare("DELETE FROM tags WHERE event_id = ?").bind(eventId),
          session.prepare("DELETE FROM content_hashes WHERE event_id = ?").bind(eventId),
          session.prepare("DELETE FROM event_tags_cache_multi WHERE event_id = ?").bind(eventId),
          session.prepare("DELETE FROM events WHERE id = ?").bind(eventId),
        );
      }

      // Execute in chunks of 100 (D1 batch limit)
      for (let i = 0; i < deleteStatements.length; i += 100) {
        await session.batch(deleteStatements.slice(i, i + 100));
      }

      deletedCount = idsToDelete.length;
      console.log(`Batch deleted ${deletedCount} events from D1.`);
    } catch (error) {
      console.error('Error batch deleting events:', error);
      errors.push('error batch deleting events');
    }
  }

  // Save the deletion event itself
  const saveResult = await saveEventToDatabase(event, env);

  if (errors.length > 0) {
    return { success: false, message: errors[0], bookmark: saveResult.bookmark ?? (session.getBookmark() ?? undefined) };
  }

  return {
    success: true,
    message: deletedCount > 0 ? `Successfully deleted ${deletedCount} event(s)` : "No matching events found to delete",
    bookmark: saveResult.bookmark ?? (session.getBookmark() ?? undefined)
  };
}

// Query handling
async function queryEvents(filters: NostrFilter[], bookmark: string, env: Env): Promise<QueryResult> {
  try {
    console.log(`Processing query with ${filters.length} filters and bookmark: ${bookmark}`);
    const session = env.RELAY_DATABASE.withSession(bookmark);
    const eventSet = new Map<string, NostrEvent>();

    // Separate filters into chunked vs batchable
    const chunkedFilters: NostrFilter[] = [];
    const batchableFilters: NostrFilter[] = [];

    for (const filter of filters) {
      // Check query complexity
      const complexity = calculateQueryComplexity(filter);
      if (complexity > MAX_QUERY_COMPLEXITY) {
        console.warn(`Query too complex (complexity: ${complexity}), skipping filter`);
        continue;
      }

      // Check if any array in the filter exceeds chunk size
      const needsChunking = (
        (filter.ids && filter.ids.length > CHUNK_SIZE) ||
        (filter.authors && filter.authors.length > CHUNK_SIZE) ||
        (filter.kinds && filter.kinds.length > CHUNK_SIZE) ||
        Object.entries(filter).some(([key, values]) =>
          key.startsWith('#') && Array.isArray(values) && values.length > CHUNK_SIZE
        )
      );

      if (needsChunking) {
        chunkedFilters.push(filter);
      } else {
        batchableFilters.push(filter);
      }
    }

    // Execute chunked filters sequentially
    let totalEventsRead = 0;
    for (const filter of chunkedFilters) {
      if (totalEventsRead >= GLOBAL_MAX_EVENTS) {
        console.warn(`Global event limit reached (${GLOBAL_MAX_EVENTS}), stopping query`);
        break;
      }

      console.log(`Filter has arrays >${CHUNK_SIZE} items, using chunked query...`);
      const chunkedResult = await queryDatabaseChunked(filter, bookmark, env);
      for (const event of chunkedResult.events) {
        if (totalEventsRead >= GLOBAL_MAX_EVENTS) break;
        eventSet.set(event.id, event);
        totalEventsRead++;
      }
    }

    // Execute batchable filters in parallel using D1 batch API
    if (batchableFilters.length > 0 && totalEventsRead < GLOBAL_MAX_EVENTS) {
      // Precheck expensive tag queries with COUNT
      const validFilters: NostrFilter[] = [];
      for (const filter of batchableFilters) {
        // Only precheck if filter has tag filters
        const hasTagFilters = Object.keys(filter).some(key => key.startsWith('#'));

        if (hasTagFilters) {
          const countQuery = buildCountQuery(filter);
          const countResult = await session.prepare(countQuery.sql).bind(...countQuery.params).first() as { count: number } | null;
          const estimatedRows = (countResult?.count as number) || 0;

          if (estimatedRows > 10000) {
            console.warn(`Query precheck: estimated ${estimatedRows} rows, skipping filter to prevent timeout`);
            continue;
          } else {
            console.log(`Query precheck: estimated ${estimatedRows} rows, proceeding`);
          }
        }

        validFilters.push(filter);
      }

      if (validFilters.length === 0) {
        console.warn('All filters were too expensive after COUNT precheck');
      } else {
        const queries = validFilters.map(filter => {
          const query = buildQuery(filter);
          return session.prepare(query.sql).bind(...query.params);
        });

        try {
          const results = await session.batch(queries);

          // Collect all rows first
          const allRows: any[] = [];

          // Process all batch results
          for (let i = 0; i < results.length; i++) {
            const result = results[i];

            // Log query metadata for first result
            if (i === 0 && result.meta) {
              console.log({
                servedByRegion: result.meta.served_by_region ?? "",
                servedByPrimary: result.meta.served_by_primary ?? false,
                batchSize: results.length
              });
            }

            if (result.success && result.results) {
              for (const row of result.results as any[]) {
                if (totalEventsRead >= GLOBAL_MAX_EVENTS) break;
                allRows.push(row);
                totalEventsRead++;
              }
            } else if (!result.success) {
              console.error(`Batch query ${i} failed:`, result.error);
            }
          }

          // Build events from collected rows
          for (const row of allRows) {
            const event: NostrEvent = {
              id: row.id as string,
              pubkey: row.pubkey as string,
              created_at: row.created_at as number,
              kind: row.kind as number,
              tags: JSON.parse(row.tags as string),
              content: row.content as string,
              sig: row.sig as string
            };
            eventSet.set(event.id, event);
          }
        } catch (error: any) {
          console.error(`Batch query execution error: ${error.message}`);
          throw error;
        }
      }
    }

    const events = Array.from(eventSet.values()).sort((a, b) => {
      if (b.created_at !== a.created_at) {
        return b.created_at - a.created_at;
      }
      return a.id.localeCompare(b.id);
    });

    const newBookmark = session.getBookmark();
    console.log(`Found ${events.length} events. New bookmark: ${newBookmark}`);
    return { events, bookmark: newBookmark };

  } catch (error: any) {
    console.error(`Error querying events: ${error.message}`);
    return { events: [], bookmark: null };
  }
}

function handleRelayInfoRequest(request: Request): Response {
  const responseInfo = { ...relayInfo };

  if (PAY_TO_RELAY_ENABLED) {
    const url = new URL(request.url);
    responseInfo.payments_url = `${url.protocol}//${url.host}`;
    responseInfo.fees = {
      admission: [{ amount: RELAY_ACCESS_PRICE_SATS * 1000, unit: "msats" }]
    };
  }

  return new Response(JSON.stringify(responseInfo), {
    status: 200,
    headers: {
      "Content-Type": "application/nostr+json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type, Accept",
      "Access-Control-Allow-Methods": "GET",
    }
  });
}

async function serveFavicon(): Promise<Response> {
  const response = await fetch(relayInfo.icon);
  if (response.ok) {
    const headers = new Headers(response.headers);
    headers.set("Cache-Control", "max-age=3600");
    return new Response(response.body, {
      status: response.status,
      headers: headers,
    });
  }
  return new Response(null, { status: 404 });
}

function handleNIP05Request(url: URL): Response {
  const name = url.searchParams.get("name");
  if (!name) {
    return new Response(JSON.stringify({ error: "Missing 'name' parameter" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  const pubkey = nip05Users[name.toLowerCase()];
  if (!pubkey) {
    return new Response(JSON.stringify({ error: "User not found" }), {
      status: 404,
      headers: { "Content-Type": "application/json" }
    });
  }

  const response = {
    names: { [name]: pubkey },
    relays: { [pubkey]: [] }
  };

  return new Response(JSON.stringify(response), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*"
    }
  });
}

async function handleCheckPayment(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const pubkey = url.searchParams.get('pubkey');

  if (!pubkey) {
    return new Response(JSON.stringify({ error: 'Missing pubkey' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const paid = await hasPaidForRelay(pubkey, env);

  if (paid === null) {
    return new Response(JSON.stringify({ error: 'Unable to verify payment status' }), {
      status: 503,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  }

  return new Response(JSON.stringify({ paid }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

// Payment notification: the client submits its kind 9735 zap receipt after
// paying the Lightning invoice; the relay verifies the receipt
// cryptographically and records the payer. (Replaces the previous
// unauthenticated `?npub=` marking, which let anyone mark any pubkey as paid
// without proof of payment.)
async function handlePaymentNotification(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  try {
    const body = await request.json() as { event?: NostrEvent };
    const receipt = body?.event;

    if (!receipt) {
      return new Response(JSON.stringify({ error: 'Missing zap receipt event' }), {
        status: 400,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    const verified = await verifyZapReceipt(receipt, relayNpub, RELAY_ACCESS_PRICE_SATS, verifyEventSignature, LNURL_SERVER_PUBKEY, PAYEE_LUD16);
    if (!verified) {
      return new Response(JSON.stringify({ error: 'Invalid zap receipt' }), {
        status: 403,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    // Persist the receipt event itself (best-effort audit trail), then record access.
    await saveEventToDatabase(receipt, env).catch(() => undefined);
    const success = await savePaidPubkey(verified.payer, env, verified.amountSats);

    return new Response(JSON.stringify({
      success,
      pubkey: verified.payer,
      message: success ? 'Payment recorded successfully' : 'Failed to save payment'
    }), {
      status: success ? 200 : 500,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  } catch (error) {
    console.error('Error processing payment notification:', error);
    return new Response(JSON.stringify({ error: 'Invalid request' }), {
      status: 400,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
}

// Multi-region DO selection logic with location hints
async function getOptimalDO(cf: any, env: Env, url: URL): Promise<{ stub: DurableObjectStub; doName: string }> {
  const continent = cf?.continent || 'NA';
  const country = cf?.country || 'US';
  const region = cf?.region || 'unknown';
  const colo = cf?.colo || 'unknown';

  console.log(`User location: continent=${continent}, country=${country}, region=${region}, colo=${colo}`);

  // All 9 endpoints with their location hints
  const ALL_ENDPOINTS = [
    { name: 'relay-WNAM-primary', hint: 'wnam' },
    { name: 'relay-ENAM-primary', hint: 'enam' },
    { name: 'relay-WEUR-primary', hint: 'weur' },
    { name: 'relay-EEUR-primary', hint: 'eeur' },
    { name: 'relay-APAC-primary', hint: 'apac' },
    { name: 'relay-OC-primary', hint: 'oc' },
    { name: 'relay-SAM-primary', hint: 'sam' },
    { name: 'relay-AFR-primary', hint: 'afr' },
    { name: 'relay-ME-primary', hint: 'me' }
  ];

  // Country to hint mapping
  const countryToHint: Record<string, string> = {
    // North America
    'US': 'enam', 'CA': 'enam', 'MX': 'wnam',

    // Central America & Caribbean (route to WNAM)
    'GT': 'wnam', 'BZ': 'wnam', 'SV': 'wnam', 'HN': 'wnam', 'NI': 'wnam',
    'CR': 'wnam', 'PA': 'wnam', 'CU': 'wnam', 'DO': 'wnam', 'HT': 'wnam',
    'JM': 'wnam', 'PR': 'wnam', 'TT': 'wnam', 'BB': 'wnam',

    // South America
    'BR': 'sam', 'AR': 'sam', 'CL': 'sam', 'CO': 'sam', 'PE': 'sam',
    'VE': 'sam', 'EC': 'sam', 'BO': 'sam', 'PY': 'sam', 'UY': 'sam',
    'GY': 'sam', 'SR': 'sam', 'GF': 'sam',

    // Western Europe
    'GB': 'weur', 'FR': 'weur', 'DE': 'weur', 'ES': 'weur', 'IT': 'weur',
    'NL': 'weur', 'BE': 'weur', 'CH': 'weur', 'AT': 'weur', 'PT': 'weur',
    'IE': 'weur', 'LU': 'weur', 'MC': 'weur', 'AD': 'weur', 'SM': 'weur',
    'VA': 'weur', 'LI': 'weur', 'MT': 'weur',

    // Nordic countries (route to WEUR)
    'SE': 'weur', 'NO': 'weur', 'DK': 'weur', 'FI': 'weur', 'IS': 'weur',

    // Eastern Europe
    'PL': 'eeur', 'RU': 'eeur', 'UA': 'eeur', 'RO': 'eeur', 'CZ': 'eeur',
    'HU': 'eeur', 'GR': 'eeur', 'BG': 'eeur', 'SK': 'eeur', 'HR': 'eeur',
    'RS': 'eeur', 'SI': 'eeur', 'BA': 'eeur', 'AL': 'eeur', 'MK': 'eeur',
    'ME': 'eeur', 'XK': 'eeur', 'BY': 'eeur', 'MD': 'eeur', 'LT': 'eeur',
    'LV': 'eeur', 'EE': 'eeur', 'CY': 'eeur',

    // Asia-Pacific
    'JP': 'apac', 'CN': 'apac', 'KR': 'apac', 'IN': 'apac', 'SG': 'apac',
    'TH': 'apac', 'ID': 'apac', 'MY': 'apac', 'VN': 'apac', 'PH': 'apac',
    'TW': 'apac', 'HK': 'apac', 'MO': 'apac', 'KH': 'apac', 'LA': 'apac',
    'MM': 'apac', 'BD': 'apac', 'LK': 'apac', 'NP': 'apac', 'BT': 'apac',
    'MV': 'apac', 'PK': 'apac', 'AF': 'apac', 'MN': 'apac', 'KP': 'apac',
    'BN': 'apac', 'TL': 'apac', 'PG': 'apac', 'FJ': 'apac', 'SB': 'apac',
    'VU': 'apac', 'NC': 'apac', 'PF': 'apac', 'WS': 'apac', 'TO': 'apac',
    'KI': 'apac', 'PW': 'apac', 'MH': 'apac', 'FM': 'apac', 'NR': 'apac',
    'TV': 'apac', 'CK': 'apac', 'NU': 'apac', 'TK': 'apac', 'GU': 'apac',
    'MP': 'apac', 'AS': 'apac',

    // Oceania
    'AU': 'oc', 'NZ': 'oc',

    // Middle East
    'AE': 'me', 'SA': 'me', 'IL': 'me', 'TR': 'me', 'EG': 'me',
    'IQ': 'me', 'IR': 'me', 'SY': 'me', 'JO': 'me', 'LB': 'me',
    'KW': 'me', 'QA': 'me', 'BH': 'me', 'OM': 'me', 'YE': 'me',
    'PS': 'me', 'GE': 'me', 'AM': 'me', 'AZ': 'me',

    // Africa
    'ZA': 'afr', 'NG': 'afr', 'KE': 'afr', 'MA': 'afr', 'TN': 'afr',
    'DZ': 'afr', 'LY': 'afr', 'ET': 'afr', 'GH': 'afr', 'TZ': 'afr',
    'UG': 'afr', 'SD': 'afr', 'AO': 'afr', 'MZ': 'afr', 'MG': 'afr',
    'CM': 'afr', 'CI': 'afr', 'NE': 'afr', 'BF': 'afr', 'ML': 'afr',
    'MW': 'afr', 'ZM': 'afr', 'SN': 'afr', 'SO': 'afr', 'TD': 'afr',
    'ZW': 'afr', 'GN': 'afr', 'RW': 'afr', 'BJ': 'afr', 'BI': 'afr',
    'TG': 'afr', 'SL': 'afr', 'LR': 'afr', 'MR': 'afr', 'CF': 'afr',
    'ER': 'afr', 'GM': 'afr', 'BW': 'afr', 'NA': 'afr', 'GA': 'afr',
    'LS': 'afr', 'GW': 'afr', 'GQ': 'afr', 'MU': 'afr', 'SZ': 'afr',
    'DJ': 'afr', 'KM': 'afr', 'CV': 'afr', 'SC': 'afr', 'ST': 'afr',
    'SS': 'afr', 'EH': 'afr', 'CG': 'afr', 'CD': 'afr',

    // Central Asia (route to APAC)
    'KZ': 'apac', 'UZ': 'apac', 'TM': 'apac', 'TJ': 'apac', 'KG': 'apac',
  };

  // US state-level routing
  const usStateToHint: Record<string, string> = {
    // Western states -> WNAM
    'California': 'wnam', 'Oregon': 'wnam', 'Washington': 'wnam', 'Nevada': 'wnam', 'Arizona': 'wnam',
    'Utah': 'wnam', 'Idaho': 'wnam', 'Montana': 'wnam', 'Wyoming': 'wnam', 'Colorado': 'wnam',
    'New Mexico': 'wnam', 'Alaska': 'wnam', 'Hawaii': 'wnam',

    // Eastern states -> ENAM
    'New York': 'enam', 'Florida': 'enam', 'Texas': 'enam', 'Illinois': 'enam', 'Georgia': 'enam',
    'Pennsylvania': 'enam', 'Ohio': 'enam', 'Michigan': 'enam', 'North Carolina': 'enam', 'Virginia': 'enam',
    'Massachusetts': 'enam', 'New Jersey': 'enam', 'Maryland': 'enam', 'Connecticut': 'enam', 'Maine': 'enam',
    'New Hampshire': 'enam', 'Vermont': 'enam', 'Rhode Island': 'enam', 'South Carolina': 'enam', 'Tennessee': 'enam',
    'Alabama': 'enam', 'Mississippi': 'enam', 'Louisiana': 'enam', 'Arkansas': 'enam', 'Missouri': 'enam',
    'Iowa': 'enam', 'Minnesota': 'enam', 'Wisconsin': 'enam', 'Indiana': 'enam', 'Kentucky': 'enam',
    'West Virginia': 'enam', 'Delaware': 'enam', 'Oklahoma': 'enam', 'Kansas': 'enam', 'Nebraska': 'enam',
    'South Dakota': 'enam', 'North Dakota': 'enam',

    // DC
    'District of Columbia': 'enam',
  };

  // Continent to hint fallback
  const continentToHint: Record<string, string> = {
    'NA': 'enam',
    'SA': 'sam',
    'EU': 'weur',
    'AS': 'apac',
    'AF': 'afr',
    'OC': 'oc'
  };

  // Determine best hint 
  let bestHint: string;

  // Only check US states if country is actually US
  if (country === 'US' && region && region !== 'unknown') {
    bestHint = usStateToHint[region] || 'enam';
  } else {
    // First try country mapping, then continent fallback
    bestHint = countryToHint[country] || continentToHint[continent] || 'enam';
  }

  // Find the primary endpoint based on hint
  const primaryEndpoint = ALL_ENDPOINTS.find(ep => ep.hint === bestHint) || ALL_ENDPOINTS[1]; // Default to ENAM

  // Order endpoints by proximity (primary first, then others)
  const orderedEndpoints = [
    primaryEndpoint,
    ...ALL_ENDPOINTS.filter(ep => ep.name !== primaryEndpoint.name)
  ];

  // Try each endpoint
  for (const endpoint of orderedEndpoints) {
    try {
      const id = env.RELAY_WEBSOCKET.idFromName(endpoint.name);
      const stub = env.RELAY_WEBSOCKET.get(id, { locationHint: endpoint.hint });

      console.log(`Connected to DO: ${endpoint.name} (hint: ${endpoint.hint})`);
      // @ts-ignore
      return { stub, doName: endpoint.name };
    } catch (error) {
      console.log(`Failed to connect to ${endpoint.name}: ${error}`);
    }
  }

  // Fallback to ENAM
  const fallback = ALL_ENDPOINTS[1]; // ENAM
  const id = env.RELAY_WEBSOCKET.idFromName(fallback.name);
  const stub = env.RELAY_WEBSOCKET.get(id, { locationHint: fallback.hint });
  console.log(`Fallback to DO: ${fallback.name} (hint: ${fallback.hint})`);
  // @ts-ignore
  return { stub, doName: fallback.name };
}

// Export functions for use by Durable Object
export {
  verifyEventSignature,
  hasPaidForRelay,
  processEvent,
  queryEvents,
  calculateQueryComplexity
};

// Main worker export with Durable Object
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      const url = new URL(request.url);

      // Payment endpoints
      if (request.method === 'POST' && url.searchParams.has('notify-zap') && PAY_TO_RELAY_ENABLED) {
        return await handlePaymentNotification(request, env);
      }

      if (url.pathname === "/api/check-payment" && PAY_TO_RELAY_ENABLED) {
        return await handleCheckPayment(request, env);
      }

      // Main endpoints
      if (url.pathname === "/") {
        if (request.headers.get("Upgrade") === "websocket") {
          // Get Cloudflare location info
          const cf = (request as any).cf;

          // Get optimal DO based on user location
          const { stub, doName } = await getOptimalDO(cf, env, url);

          // Add location info to the request
          const newUrl = new URL(request.url);
          newUrl.searchParams.set('region', cf?.region || 'unknown');
          newUrl.searchParams.set('colo', cf?.colo || 'unknown');
          newUrl.searchParams.set('continent', cf?.continent || 'unknown');
          newUrl.searchParams.set('country', cf?.country || 'unknown');
          newUrl.searchParams.set('doName', doName);

          return stub.fetch(new Request(newUrl, request));
        } else if (request.headers.get("Accept") === "application/nostr+json") {
          return handleRelayInfoRequest(request);
        } else {
          // Initialize database in background
          ctx.waitUntil(
            initializeDatabase(env.RELAY_DATABASE)
              .catch(e => console.error("DB init error:", e))
          );
          return serveLandingPage();
        }
      } else if (url.pathname === "/.well-known/nostr.json") {
        return handleNIP05Request(url);
      } else if (url.pathname === "/favicon.ico") {
        return await serveFavicon();
      } else {
        return new Response("Invalid request", { status: 400 });
      }
    } catch (error) {
      console.error("Error in fetch handler:", error);
      return new Response("Internal Server Error", { status: 500 });
    }
  },

  // Scheduled handler for 24hr database maintenance (runs daily at 00:00 UTC)
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    console.log('Running scheduled 24hr database maintenance...');

    try {
      const session = env.RELAY_DATABASE.withSession('first-primary');

      // Check database size and prune if necessary (D1 has a 10GB limit)
      if (DB_PRUNING_ENABLED) {
        const currentSizeBytes = await getDatabaseSizeBytes(session);
        const currentSizeGB = currentSizeBytes / (1024 * 1024 * 1024);
        console.log(`Current database size: ${currentSizeGB.toFixed(2)} GB (threshold: ${DB_SIZE_THRESHOLD_GB} GB)`);

        if (currentSizeGB >= DB_SIZE_THRESHOLD_GB) {
          console.log(`Database size (${currentSizeGB.toFixed(2)} GB) exceeds threshold (${DB_SIZE_THRESHOLD_GB} GB). Starting pruning...`);
          const targetSizeBytes = DB_PRUNE_TARGET_GB * 1024 * 1024 * 1024;
          const pruneResult = await pruneOldEvents(session, targetSizeBytes);
          console.log(`Pruning completed. Deleted ${pruneResult.eventsDeleted} events. Final size: ${(pruneResult.finalSizeBytes / (1024 * 1024 * 1024)).toFixed(2)} GB`);
        } else {
          console.log('Database size is within limits. No pruning needed.');
        }
      } else {
        console.log('Database pruning is disabled.');
      }

      // Run PRAGMA optimize (SQLite's intelligent optimization)
      console.log('Running PRAGMA optimize...');
      await session.prepare('PRAGMA optimize').run();
      console.log('PRAGMA optimize completed');

      // Run ANALYZE to update query planner statistics
      console.log('Running ANALYZE on all tables...');
      await session.prepare('ANALYZE events').run();
      await session.prepare('ANALYZE tags').run();
      await session.prepare('ANALYZE event_tags_cache_multi').run();
      await session.prepare('ANALYZE content_hashes').run();
      console.log('ANALYZE completed - query planner statistics updated');

      console.log('Scheduled 24hr database maintenance completed successfully');
    } catch (error) {
      console.error('Scheduled maintenance failed:', error);
    }
  }
};

// Export the Durable Object class
export { RelayWebSocket };
