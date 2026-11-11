import { pruneProtectedKinds, DB_PRUNE_BATCH_SIZE } from './config';

// Database initialization
export async function initializeDatabase(db: D1Database): Promise<void> {
  const dropSession = db.withSession('first-primary');

  try {
    await dropSession.prepare(`
      CREATE TABLE IF NOT EXISTS system_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        created_at INTEGER DEFAULT (strftime('%s', 'now'))
      )
    `).run();
  } catch (_) {}

  const cleanupDone = await dropSession.prepare(
    "SELECT value FROM system_config WHERE key = 'cleanup_v1' LIMIT 1"
  ).first().catch(() => null);

  if (!cleanupDone || cleanupDone.value !== '1') {
    const dropIndexes = [
      'idx_events_pubkey',
      'idx_events_kind',
      'idx_events_created_at_kind',
      'idx_events_authors_kinds',
      'idx_events_tag_p_created_at',
      'idx_events_tag_e_created_at',
      'idx_events_tag_a_created_at',
      'idx_events_tag_t_created_at',
      'idx_events_tag_d_created_at',
      'idx_events_tag_r_created_at',
      'idx_events_tag_L_created_at',
      'idx_events_tag_s_created_at',
      'idx_events_tag_u_created_at',
      'idx_events_kind_tag_p',
      'idx_events_kind_tag_e',
      'idx_events_kind_tag_a',
      'idx_events_kind_tag_t',
      'idx_events_kind_tag_L',
      'idx_events_kind_tag_s',
      'idx_events_reply_to',
      'idx_events_root_thread',
      'idx_events_kind_created_at_covering',
      'idx_events_pubkey_kind_created_at_covering',
      'idx_events_created_at_covering',
      'idx_events_kind_pubkey_created_at_covering',
      'idx_tags_name_value',
      'idx_tags_value',
      'idx_tags_name_value_event_created',
    ];
    for (const idx of dropIndexes) {
      await dropSession.prepare(`DROP INDEX IF EXISTS ${idx}`).run();
    }

    const dropTables = ['event_tags_cache', 'mv_follow_graph', 'mv_recent_notes', 'mv_timeline_cache'];
    for (const tbl of dropTables) {
      await dropSession.prepare(`DROP TABLE IF EXISTS ${tbl}`).run();
    }

    await dropSession.prepare(
      "INSERT OR REPLACE INTO system_config (key, value) VALUES ('cleanup_v1', '1')"
    ).run();
  }

  try {
    const initCheck = await dropSession.prepare(
      "SELECT value FROM system_config WHERE key = 'db_initialized' LIMIT 1"
    ).first().catch(() => null);

    if (initCheck && initCheck.value === '1') {
      console.log("Database already initialized");
      return;
    }
  } catch (error) {
    console.log("Database not initialized, creating schema...");
  }

  const session = db.withSession('first-primary');

  try {
    await session.prepare(`
      CREATE TABLE IF NOT EXISTS system_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        created_at INTEGER DEFAULT (strftime('%s', 'now'))
      )
    `).run();

    const statements = [
      `CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        pubkey TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        kind INTEGER NOT NULL,
        tags TEXT NOT NULL,
        content TEXT NOT NULL,
        sig TEXT NOT NULL,
        created_timestamp INTEGER DEFAULT (strftime('%s', 'now')),
        tag_p TEXT,
        tag_e TEXT,
        tag_a TEXT,
        tag_t TEXT,
        tag_d TEXT,
        tag_r TEXT,
        tag_L TEXT,
        tag_s TEXT,
        tag_u TEXT,
        reply_to_event_id TEXT,
        root_event_id TEXT,
        content_preview TEXT
      )`,

      `CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_events_kind_created_at ON events(kind, created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_events_pubkey_created_at ON events(pubkey, created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_events_pubkey_kind_created_at ON events(pubkey, kind, created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_events_kind_pubkey_created_at ON events(kind, pubkey, created_at DESC)`,

      `CREATE TABLE IF NOT EXISTS tags (
        event_id TEXT NOT NULL,
        tag_name TEXT NOT NULL,
        tag_value TEXT NOT NULL,
        FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
      )`,
      `CREATE INDEX IF NOT EXISTS idx_tags_name_value_event ON tags(tag_name, tag_value, event_id)`,
      `CREATE INDEX IF NOT EXISTS idx_tags_event_id ON tags(event_id)`,

      `CREATE TABLE IF NOT EXISTS event_tags_cache_multi (
        event_id TEXT NOT NULL,
        pubkey TEXT NOT NULL,
        kind INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        tag_type TEXT NOT NULL CHECK(tag_type IN ('p', 'e', 'a', 't', 'd', 'r', 'L', 's', 'u')),
        tag_value TEXT NOT NULL,
        PRIMARY KEY (event_id, tag_type, tag_value)
      )`,
      `CREATE INDEX IF NOT EXISTS idx_cache_multi_type_value_time ON event_tags_cache_multi(tag_type, tag_value, created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_cache_multi_type_value_event ON event_tags_cache_multi(tag_type, tag_value, event_id)`,
      `CREATE INDEX IF NOT EXISTS idx_cache_multi_kind_type_value ON event_tags_cache_multi(kind, tag_type, tag_value, created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_cache_multi_event_id ON event_tags_cache_multi(event_id)`,

      `CREATE TABLE IF NOT EXISTS paid_pubkeys (
        pubkey TEXT PRIMARY KEY,
        paid_at INTEGER NOT NULL,
        amount_sats INTEGER,
        created_timestamp INTEGER DEFAULT (strftime('%s', 'now'))
      )`,

      `CREATE TABLE IF NOT EXISTS content_hashes (
        hash TEXT PRIMARY KEY,
        event_id TEXT NOT NULL,
        pubkey TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
      )`,
      `CREATE INDEX IF NOT EXISTS idx_content_hashes_pubkey ON content_hashes(pubkey)`,
      `CREATE INDEX IF NOT EXISTS idx_content_hashes_created_at ON content_hashes(created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_content_hashes_pubkey_created ON content_hashes(pubkey, created_at DESC)`
    ];

    for (const statement of statements) {
      await session.prepare(statement).run();
    }

    await session.prepare("PRAGMA foreign_keys = ON").run();
    await session.prepare(
      "INSERT OR REPLACE INTO system_config (key, value) VALUES ('db_initialized', '1')"
    ).run();

    // Check current schema version
    const versionResult = await session.prepare(
      "SELECT value FROM system_config WHERE key = 'schema_version'"
    ).first() as { value: string } | null;
    const currentVersion = versionResult ? parseInt(versionResult.value) : 0;

    if (currentVersion < 5) {
      console.log('Migrating to schema version 5: adding and populating tag columns in events table...');

      // Add tag columns if they don't exist (for databases created before these columns were in CREATE TABLE)
      const v5Columns = ['tag_p', 'tag_e', 'tag_a', 'tag_t', 'tag_d', 'tag_r'];
      for (const col of v5Columns) {
        try {
          await session.prepare(`ALTER TABLE events ADD COLUMN ${col} TEXT`).run();
        } catch (e: any) {
          // Column already exists — safe to ignore
          if (!e.message?.includes('duplicate column')) throw e;
        }
      }

      await session.prepare(`
        UPDATE events
        SET
          tag_p = (SELECT tag_value FROM tags WHERE event_id = events.id AND tag_name = 'p' LIMIT 1),
          tag_e = (SELECT tag_value FROM tags WHERE event_id = events.id AND tag_name = 'e' LIMIT 1),
          tag_a = (SELECT tag_value FROM tags WHERE event_id = events.id AND tag_name = 'a' LIMIT 1),
          tag_t = (SELECT tag_value FROM tags WHERE event_id = events.id AND tag_name = 't' LIMIT 1),
          tag_d = (SELECT tag_value FROM tags WHERE event_id = events.id AND tag_name = 'd' LIMIT 1),
          tag_r = (SELECT tag_value FROM tags WHERE event_id = events.id AND tag_name = 'r' LIMIT 1)
        WHERE EXISTS (
          SELECT 1 FROM tags t
          WHERE t.event_id = events.id
          AND t.tag_name IN ('p', 'e', 'a', 't', 'd', 'r')
        )
      `).run();

      console.log('Schema v5 migration completed');
    }

    if (currentVersion < 6) {
      console.log('Migrating to schema version 6: adding L/s/u tags and thread metadata...');

      // Add columns if they don't exist (for databases created before these columns were in CREATE TABLE)
      const v6Columns = ['tag_L', 'tag_s', 'tag_u', 'reply_to_event_id', 'root_event_id', 'content_preview'];
      for (const col of v6Columns) {
        try {
          await session.prepare(`ALTER TABLE events ADD COLUMN ${col} TEXT`).run();
        } catch (e: any) {
          // Column already exists — safe to ignore
          if (!e.message?.includes('duplicate column')) throw e;
        }
      }

      await session.prepare(`
        UPDATE events
        SET
          tag_L = (SELECT tag_value FROM tags WHERE event_id = events.id AND tag_name = 'L' LIMIT 1),
          tag_s = (SELECT tag_value FROM tags WHERE event_id = events.id AND tag_name = 's' LIMIT 1),
          tag_u = (SELECT tag_value FROM tags WHERE event_id = events.id AND tag_name = 'u' LIMIT 1),
          reply_to_event_id = (SELECT tag_value FROM tags WHERE event_id = events.id AND tag_name = 'e' LIMIT 1),
          root_event_id = (
            SELECT tag_value FROM tags
            WHERE event_id = events.id AND tag_name = 'e'
            AND EXISTS (
              SELECT 1 FROM tags t2
              WHERE t2.event_id = events.id AND t2.tag_name = 'e'
              HAVING COUNT(*) > 1
            )
            ORDER BY ROWID DESC LIMIT 1
          ),
          content_preview = SUBSTR(content, 1, 100)
        WHERE EXISTS (
          SELECT 1 FROM tags t
          WHERE t.event_id = events.id
          AND t.tag_name IN ('L', 's', 'u', 'e')
        ) OR LENGTH(content) > 0
      `).run();

      console.log('Schema v6 migration completed');
    }

    await session.prepare(
      "INSERT OR REPLACE INTO system_config (key, value) VALUES ('schema_version', '6')"
    ).run();

    // Populate multi-value cache from existing data
    await session.prepare(`
      INSERT OR IGNORE INTO event_tags_cache_multi (event_id, pubkey, kind, created_at, tag_type, tag_value)
      SELECT
        e.id,
        e.pubkey,
        e.kind,
        e.created_at,
        t.tag_name,
        t.tag_value
      FROM events e
      INNER JOIN tags t ON e.id = t.event_id
      WHERE t.tag_name IN ('p', 'e', 'a', 't', 'd', 'r', 'L', 's', 'u')
    `).run();

    // Run ANALYZE to initialize statistics
    await session.prepare("ANALYZE events").run();
    await session.prepare("ANALYZE tags").run();
    await session.prepare("ANALYZE event_tags_cache_multi").run();

    console.log("Database initialization completed!");
  } catch (error) {
    console.error("Failed to initialize database:", error);
    throw error;
  }
}


// Database pruning helper functions

// Get the current database size in bytes
export async function getDatabaseSizeBytes(session: D1DatabaseSession): Promise<number> {
  try {
    const result = await session.prepare('SELECT 1').run();
    const sizeAfter = (result.meta as { size_after?: number } | undefined)?.size_after;

    if (typeof sizeAfter === 'number' && sizeAfter > 0) {
      return sizeAfter;
    }
    return 0;
  } catch (error) {
    console.error('Error getting database size:', error);
    return 0;
  }
}

// Prune old events to reduce database size
// Returns the number of events deleted
export async function pruneOldEvents(session: D1DatabaseSession, targetSizeBytes: number): Promise<{ eventsDeleted: number; finalSizeBytes: number }> {
  let totalEventsDeleted = 0;
  let currentSize = await getDatabaseSizeBytes(session);

  console.log(`Starting database pruning. Current size: ${(currentSize / (1024 * 1024 * 1024)).toFixed(2)} GB, Target: ${(targetSizeBytes / (1024 * 1024 * 1024)).toFixed(2)} GB`);

  // Build the protected kinds clause for SQL
  const protectedKindsArray = Array.from(pruneProtectedKinds);
  const protectedKindsClause = protectedKindsArray.length > 0
    ? `AND kind NOT IN (${protectedKindsArray.join(',')})`
    : '';

  // Keep pruning in batches until we reach target size
  while (currentSize > targetSizeBytes) {
    // Find the oldest events (excluding protected kinds)
    const oldestEvents = await session.prepare(`
      SELECT id FROM events
      WHERE 1=1 ${protectedKindsClause}
      ORDER BY created_at ASC
      LIMIT ?
    `).bind(DB_PRUNE_BATCH_SIZE).all();

    if (!oldestEvents.results || oldestEvents.results.length === 0) {
      console.log('No more events eligible for pruning');
      break;
    }

    const eventIds = oldestEvents.results.map((row: any) => row.id as string);
    const placeholders = eventIds.map(() => '?').join(',');

    // Batch all deletes into a single D1 round-trip
    const pruneResults = await session.batch([
      session.prepare(`DELETE FROM event_tags_cache_multi WHERE event_id IN (${placeholders})`).bind(...eventIds),
      session.prepare(`DELETE FROM events WHERE id IN (${placeholders})`).bind(...eventIds),
    ]);

    const deletedCount = pruneResults[1]?.meta?.changes || eventIds.length;
    totalEventsDeleted += deletedCount;

    console.log(`Pruned ${deletedCount} events (total: ${totalEventsDeleted})`);

    // Check current size after deletion
    currentSize = await getDatabaseSizeBytes(session);
    console.log(`Current database size: ${(currentSize / (1024 * 1024 * 1024)).toFixed(2)} GB`);

    // Safety break - don't delete more than 100,000 events in a single maintenance run
    if (totalEventsDeleted >= 100000) {
      console.log('Reached maximum pruning limit for this run (100,000 events)');
      break;
    }
  }

  return { eventsDeleted: totalEventsDeleted, finalSizeBytes: currentSize };
}
