import { Env, NostrEvent, NostrFilter } from './types';

// Maximum array size before a filter is split into chunked queries
export const CHUNK_SIZE = 500;

// Helper function to chunk arrays
function chunkArray<T>(array: T[], chunkSize: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < array.length; i += chunkSize) {
    chunks.push(array.slice(i, i + chunkSize));
  }
  return chunks;
}

// Only the 7 columns consumed by NostrEvent
const EVENT_COLS = 'e.id, e.pubkey, e.created_at, e.kind, e.tags, e.content, e.sig';
const EVENT_COLS_BARE = 'id, pubkey, created_at, kind, tags, content, sig';

// Build COUNT query for precheck
export function buildCountQuery(filter: NostrFilter): { sql: string; params: any[] } {
  const params: any[] = [];
  const conditions: string[] = [];

  // Count and categorize tag filters
  const directTags: Array<{ name: string; values: string[] }> = []; // Tags with direct columns (p, e, a, t, d, r)
  const otherTags: Array<{ name: string; values: string[] }> = [];

  for (const [key, values] of Object.entries(filter)) {
    if (key.startsWith('#') && Array.isArray(values) && values.length > 0) {
      const tagName = key.substring(1);
      if (['p', 'e', 'a', 't', 'd', 'r', 'L', 's', 'u'].includes(tagName)) {
        directTags.push({ name: tagName, values });
      } else {
        otherTags.push({ name: tagName, values });
      }
    }
  }

  if (directTags.length > 0 && otherTags.length === 0) {
    const cacheAlias = directTags.length === 1 ? "m" : "m0";

    if (directTags.length === 1) {
      const tagFilter = directTags[0];
      const hasKinds = filter.kinds && filter.kinds.length > 0;
      const indexHint = hasKinds && filter.kinds!.length <= 10
        ? " INDEXED BY idx_cache_multi_kind_type_value"
        : " INDEXED BY idx_cache_multi_type_value_time";
      let sql = `SELECT COUNT(DISTINCT m.event_id) as count FROM event_tags_cache_multi m${indexHint}
        WHERE m.tag_type = ? AND m.tag_value IN (${tagFilter.values.map(() => '?').join(',')})`;
      params.push(tagFilter.name, ...tagFilter.values);

      if (filter.authors && filter.authors.length > 0) {
        sql += ` AND m.pubkey IN (${filter.authors.map(() => '?').join(',')})`;
        params.push(...filter.authors);
      }
      if (hasKinds) {
        sql += ` AND m.kind IN (${filter.kinds!.map(() => '?').join(',')})`;
        params.push(...filter.kinds!);
      }
      if (filter.since) {
        sql += " AND m.created_at >= ?";
        params.push(filter.since);
      }
      if (filter.until) {
        sql += " AND m.created_at <= ?";
        params.push(filter.until);
      }
      return { sql, params };
    } else {
      const hasKindsMulti = filter.kinds && filter.kinds.length > 0;
      const firstTag = directTags[0];
      const firstHint = hasKindsMulti && filter.kinds!.length <= 10
        ? " INDEXED BY idx_cache_multi_kind_type_value"
        : " INDEXED BY idx_cache_multi_type_value_time";
      const additionalJoins = directTags.slice(1).map((t, i) => {
        const alias = `m${i + 1}`;
        const placeholders = t.values.map(() => '?').join(',');
        return `INNER JOIN event_tags_cache_multi ${alias} ON m0.event_id = ${alias}.event_id AND ${alias}.tag_type = ? AND ${alias}.tag_value IN (${placeholders})`;
      }).join('\n        ');

      let sql = `SELECT COUNT(DISTINCT m0.event_id) as count FROM event_tags_cache_multi m0${firstHint}
        ${additionalJoins}
        WHERE m0.tag_type = ? AND m0.tag_value IN (${firstTag.values.map(() => '?').join(',')})`;

      // First tag params, then additional tag params
      params.push(firstTag.name, ...firstTag.values);
      for (const tagFilter of directTags.slice(1)) {
        params.push(tagFilter.name, ...tagFilter.values);
      }

      if (filter.authors && filter.authors.length > 0) {
        sql += ` AND m0.pubkey IN (${filter.authors.map(() => '?').join(',')})`;
        params.push(...filter.authors);
      }
      if (hasKindsMulti) {
        sql += ` AND m0.kind IN (${filter.kinds!.map(() => '?').join(',')})`;
        params.push(...filter.kinds!);
      }
      if (filter.since) {
        sql += " AND m0.created_at >= ?";
        params.push(filter.since);
      }
      if (filter.until) {
        sql += " AND m0.created_at <= ?";
        params.push(filter.until);
      }
      return { sql, params };
    }
  }

  // Has non-cacheable tags
  if (directTags.length > 0 || otherTags.length > 0) {
    const allTags = [...directTags, ...otherTags];

    if (allTags.length === 1) {
      const tagFilter = allTags[0];
      let sql = `SELECT COUNT(DISTINCT e.id) as count FROM events e
        INNER JOIN tags t ON e.id = t.event_id
        WHERE t.tag_name = ? AND t.tag_value IN (${tagFilter.values.map(() => '?').join(',')})`;
      params.push(tagFilter.name, ...tagFilter.values);

      if (filter.authors && filter.authors.length > 0) {
        sql += ` AND e.pubkey IN (${filter.authors.map(() => '?').join(',')})`;
        params.push(...filter.authors);
      }
      if (filter.kinds && filter.kinds.length > 0) {
        sql += ` AND e.kind IN (${filter.kinds.map(() => '?').join(',')})`;
        params.push(...filter.kinds);
      }
      if (filter.since) {
        sql += " AND e.created_at >= ?";
        params.push(filter.since);
      }
      if (filter.until) {
        sql += " AND e.created_at <= ?";
        params.push(filter.until);
      }
      return { sql, params };
    } else {
      // Multiple tags
      const tagConditions = allTags.map(t => {
        const placeholders = t.values.map(() => '?').join(',');
        return `(t.tag_name = ? AND t.tag_value IN (${placeholders}))`;
      }).join(' OR ');

      for (const tagFilter of allTags) {
        params.push(tagFilter.name, ...tagFilter.values);
      }

      let sql = `SELECT COUNT(DISTINCT e.id) as count FROM events e
        INNER JOIN tags t ON e.id = t.event_id
        WHERE ${tagConditions}`;

      if (filter.authors && filter.authors.length > 0) {
        sql += ` AND e.pubkey IN (${filter.authors.map(() => '?').join(',')})`;
        params.push(...filter.authors);
      }
      if (filter.kinds && filter.kinds.length > 0) {
        sql += ` AND e.kind IN (${filter.kinds.map(() => '?').join(',')})`;
        params.push(...filter.kinds);
      }
      if (filter.since) {
        sql += " AND e.created_at >= ?";
        params.push(filter.since);
      }
      if (filter.until) {
        sql += " AND e.created_at <= ?";
        params.push(filter.until);
      }

      sql += ` GROUP BY e.id HAVING COUNT(DISTINCT t.tag_name) = ?`;
      params.push(allTags.length);

      // Wrap in outer SELECT to count
      sql = `SELECT COUNT(*) as count FROM (${sql})`;
      return { sql, params };
    }
  }

  // No tag filters
  let sql = "SELECT COUNT(*) as count FROM events";

  if (filter.ids && filter.ids.length > 0) {
    conditions.push(`id IN (${filter.ids.map(() => '?').join(',')})`);
    params.push(...filter.ids);
  }
  if (filter.authors && filter.authors.length > 0) {
    conditions.push(`pubkey IN (${filter.authors.map(() => '?').join(',')})`);
    params.push(...filter.authors);
  }
  if (filter.kinds && filter.kinds.length > 0) {
    conditions.push(`kind IN (${filter.kinds.map(() => '?').join(',')})`);
    params.push(...filter.kinds);
  }
  if (filter.since) {
    conditions.push("created_at >= ?");
    params.push(filter.since);
  }
  if (filter.until) {
    conditions.push("created_at <= ?");
    params.push(filter.until);
  }

  if (conditions.length > 0) {
    sql += " WHERE " + conditions.join(" AND ");
  }

  return { sql, params };
}

// Query builder
export function buildQuery(filter: NostrFilter): { sql: string; params: any[] } {
  const params: any[] = [];
  const conditions: string[] = [];

  // Count and categorize tag filters
  let tagCount = 0;
  const directTags: Array<{ name: string; values: string[] }> = []; // Tags with direct columns (p, e, a, t, d, r, L, s, u)
  const otherTags: Array<{ name: string; values: string[] }> = [];

  for (const [key, values] of Object.entries(filter)) {
    if (key.startsWith('#') && Array.isArray(values) && values.length > 0) {
      tagCount += values.length;
      const tagName = key.substring(1);

      // Check if this tag has a direct column in events table (p, e, a, t, d, r, L, s, u)
      if (['p', 'e', 'a', 't', 'd', 'r', 'L', 's', 'u'].includes(tagName)) {
        directTags.push({ name: tagName, values });
      } else {
        otherTags.push({ name: tagName, values });
      }
    }
  }

  if (directTags.length > 0 && otherTags.length === 0) {
    let sql: string;
    const whereConditions: string[] = [];
    const cacheAlias = directTags.length === 1 ? "m" : "m0";

    if (directTags.length === 1) {
      const tagFilter = directTags[0];
      const hasKinds = filter.kinds && filter.kinds.length > 0;

      let indexHint = "";
      if (hasKinds && filter.kinds!.length <= 10) {
        indexHint = " INDEXED BY idx_cache_multi_kind_type_value";
      } else {
        indexHint = " INDEXED BY idx_cache_multi_type_value_time";
      }

      sql = `SELECT DISTINCT ${EVENT_COLS} FROM events e
        INNER JOIN event_tags_cache_multi m${indexHint} ON e.id = m.event_id
        WHERE m.tag_type = ? AND m.tag_value IN (${tagFilter.values.map(() => '?').join(',')})`;
      params.push(tagFilter.name, ...tagFilter.values);
    } else {
      const hasKindsMulti = filter.kinds && filter.kinds.length > 0;
      const tagConditions = directTags.map((t, i) => {
        const alias = `m${i}`;
        const placeholders = t.values.map(() => '?').join(',');
        const hint = i === 0
          ? (hasKindsMulti && filter.kinds!.length <= 10
            ? " INDEXED BY idx_cache_multi_kind_type_value"
            : " INDEXED BY idx_cache_multi_type_value_time")
          : "";
        return `INNER JOIN event_tags_cache_multi ${alias}${hint} ON e.id = ${alias}.event_id AND ${alias}.tag_type = ? AND ${alias}.tag_value IN (${placeholders})`;
      }).join('\n        ');

      sql = `SELECT DISTINCT ${EVENT_COLS} FROM events e
        ${tagConditions}
        WHERE 1=1`;

      for (const tagFilter of directTags) {
        params.push(tagFilter.name, ...tagFilter.values);
      }
    }

    if (filter.ids && filter.ids.length > 0) {
      whereConditions.push(`e.id IN (${filter.ids.map(() => '?').join(',')})`);
      params.push(...filter.ids);
    }

    if (filter.authors && filter.authors.length > 0) {
      whereConditions.push(`e.pubkey IN (${filter.authors.map(() => '?').join(',')})`);
      params.push(...filter.authors);
    }

    if (filter.kinds && filter.kinds.length > 0) {
      whereConditions.push(`${cacheAlias}.kind IN (${filter.kinds.map(() => '?').join(',')})`);
      params.push(...filter.kinds);
    }

    if (filter.since) {
      whereConditions.push(`${cacheAlias}.created_at >= ?`);
      params.push(filter.since);
    }

    if (filter.until) {
      whereConditions.push(`${cacheAlias}.created_at <= ?`);
      params.push(filter.until);
    }

    if (filter.cursor) {
      const [timestamp, lastId] = filter.cursor.split(':');
      whereConditions.push(`(${cacheAlias}.created_at < ? OR (${cacheAlias}.created_at = ? AND e.id > ?))`);
      params.push(parseInt(timestamp), parseInt(timestamp), lastId);
    }

    if (whereConditions.length > 0) {
      sql += " AND " + whereConditions.join(" AND ");
    }

    sql += ` ORDER BY ${cacheAlias}.created_at DESC LIMIT ?`;
    params.push(Math.min(filter.limit || 500, 500));

    return { sql, params };
  }

  // Has any non-cacheable tags
  if (tagCount > 0) {
    const allTags = [...directTags, ...otherTags];

    // Single tag filter
    if (allTags.length === 1) {
      const tagFilter = allTags[0];
      let sql = `SELECT ${EVENT_COLS} FROM events e
        INNER JOIN tags t ON e.id = t.event_id
        WHERE t.tag_name = ? AND t.tag_value IN (${tagFilter.values.map(() => '?').join(',')})`;

      params.push(tagFilter.name, ...tagFilter.values);

      const whereConditions: string[] = [];

      if (filter.ids && filter.ids.length > 0) {
        whereConditions.push(`e.id IN (${filter.ids.map(() => '?').join(',')})`);
        params.push(...filter.ids);
      }

      if (filter.authors && filter.authors.length > 0) {
        whereConditions.push(`e.pubkey IN (${filter.authors.map(() => '?').join(',')})`);
        params.push(...filter.authors);
      }

      if (filter.kinds && filter.kinds.length > 0) {
        whereConditions.push(`e.kind IN (${filter.kinds.map(() => '?').join(',')})`);
        params.push(...filter.kinds);
      }

      if (filter.since) {
        whereConditions.push("e.created_at >= ?");
        params.push(filter.since);
      }

      if (filter.until) {
        whereConditions.push("e.created_at <= ?");
        params.push(filter.until);
      }

      // Cursor-based pagination support
      if (filter.cursor) {
        const [timestamp, lastId] = filter.cursor.split(':');
        whereConditions.push("(e.created_at < ? OR (e.created_at = ? AND e.id > ?))");
        params.push(parseInt(timestamp), parseInt(timestamp), lastId);
      }

      if (whereConditions.length > 0) {
        sql += " AND " + whereConditions.join(" AND ");
      }

      sql += " ORDER BY e.created_at DESC";
      sql += " LIMIT ?";
      params.push(Math.min(filter.limit || 500, 500));

      return { sql, params };
    }

    // Multiple tags
    const tagConditions = allTags.map(t => {
      const placeholders = t.values.map(() => '?').join(',');
      return `(t.tag_name = ? AND t.tag_value IN (${placeholders}))`;
    }).join(' OR ');

    // Add all parameters
    for (const tagFilter of allTags) {
      params.push(tagFilter.name, ...tagFilter.values);
    }

    let sql = `SELECT ${EVENT_COLS} FROM events e
      INNER JOIN tags t ON e.id = t.event_id
      WHERE ${tagConditions}`;

    const whereConditions: string[] = [];

    if (filter.ids && filter.ids.length > 0) {
      whereConditions.push(`e.id IN (${filter.ids.map(() => '?').join(',')})`);
      params.push(...filter.ids);
    }

    if (filter.authors && filter.authors.length > 0) {
      whereConditions.push(`e.pubkey IN (${filter.authors.map(() => '?').join(',')})`);
      params.push(...filter.authors);
    }

    if (filter.kinds && filter.kinds.length > 0) {
      whereConditions.push(`e.kind IN (${filter.kinds.map(() => '?').join(',')})`);
      params.push(...filter.kinds);
    }

    if (filter.since) {
      whereConditions.push("e.created_at >= ?");
      params.push(filter.since);
    }

    if (filter.until) {
      whereConditions.push("e.created_at <= ?");
      params.push(filter.until);
    }

    // Cursor-based pagination support
    if (filter.cursor) {
      const [timestamp, lastId] = filter.cursor.split(':');
      whereConditions.push("(e.created_at < ? OR (e.created_at = ? AND e.id > ?))");
      params.push(parseInt(timestamp), parseInt(timestamp), lastId);
    }

    if (whereConditions.length > 0) {
      sql += " AND " + whereConditions.join(" AND ");
    }

    sql += " GROUP BY e.id, e.pubkey, e.created_at, e.kind, e.tags, e.content, e.sig";
    sql += ` HAVING COUNT(DISTINCT t.tag_name) = ?`;
    params.push(allTags.length);

    sql += " ORDER BY e.created_at DESC";
    sql += " LIMIT ?";
    params.push(Math.min(filter.limit || 500, 500));

    return { sql, params };
  }

  // No tag filters - standard query with index hints
  let indexHint = "";

  const hasAuthors = filter.authors && filter.authors.length > 0;
  const hasKinds = filter.kinds && filter.kinds.length > 0;
  const hasTimeRange = filter.since || filter.until;
  const authorCount = filter.authors?.length || 0;
  const kindCount = filter.kinds?.length || 0;

  // Choose optimal index based on query pattern
  if (hasAuthors && hasKinds && authorCount <= 10 && kindCount <= 10) {
    if (authorCount <= kindCount) {
      indexHint = " INDEXED BY idx_events_pubkey_kind_created_at";
    } else {
      indexHint = " INDEXED BY idx_events_kind_pubkey_created_at";
    }
  } else if (hasAuthors && authorCount <= 5 && !hasKinds) {
    indexHint = " INDEXED BY idx_events_pubkey_created_at";
  } else if (hasKinds && kindCount <= 5 && !hasAuthors) {
    indexHint = " INDEXED BY idx_events_kind_created_at";
  } else if (hasAuthors && hasKinds && authorCount > 10) {
    indexHint = " INDEXED BY idx_events_kind_created_at";
  } else if (!hasAuthors && !hasKinds && hasTimeRange) {
    indexHint = " INDEXED BY idx_events_created_at";
  }

  let sql = `SELECT ${EVENT_COLS_BARE} FROM events${indexHint}`;

  if (filter.ids && filter.ids.length > 0) {
    conditions.push(`id IN (${filter.ids.map(() => '?').join(',')})`);
    params.push(...filter.ids);
  }

  if (filter.authors && filter.authors.length > 0) {
    conditions.push(`pubkey IN (${filter.authors.map(() => '?').join(',')})`);
    params.push(...filter.authors);
  }

  if (filter.kinds && filter.kinds.length > 0) {
    conditions.push(`kind IN (${filter.kinds.map(() => '?').join(',')})`);
    params.push(...filter.kinds);
  }

  if (filter.since) {
    conditions.push("created_at >= ?");
    params.push(filter.since);
  }

  if (filter.until) {
    conditions.push("created_at <= ?");
    params.push(filter.until);
  }

  // Cursor-based pagination support
  if (filter.cursor) {
    const [timestamp, lastId] = filter.cursor.split(':');
    conditions.push("(created_at < ? OR (created_at = ? AND id > ?))");
    params.push(parseInt(timestamp), parseInt(timestamp), lastId);
  }

  if (conditions.length > 0) {
    sql += " WHERE " + conditions.join(" AND ");
  }

  sql += " ORDER BY created_at DESC";
  sql += " LIMIT ?";
  params.push(Math.min(filter.limit || 500, 500));

  return { sql, params };
}

// Helper function to handle chunked queries
export async function queryDatabaseChunked(filter: NostrFilter, bookmark: string, env: Env): Promise<{ events: NostrEvent[] }> {
  const session = env.RELAY_DATABASE.withSession(bookmark);
  const allRows = new Map<string, any>(); // Collect rows first, dedupe by ID

  // Create a base filter with everything except the large arrays
  const baseFilter: NostrFilter = { ...filter };
  const needsChunking = {
    ids: false,
    authors: false,
    kinds: false,
    tags: {} as Record<string, boolean>
  };

  // Identify what needs chunking and remove from base filter
  if (filter.ids && filter.ids.length > CHUNK_SIZE) {
    needsChunking.ids = true;
    delete baseFilter.ids;
  }

  if (filter.authors && filter.authors.length > CHUNK_SIZE) {
    needsChunking.authors = true;
    delete baseFilter.authors;
  }

  if (filter.kinds && filter.kinds.length > CHUNK_SIZE) {
    needsChunking.kinds = true;
    delete baseFilter.kinds;
  }

  // Check tag filters
  for (const [key, values] of Object.entries(filter)) {
    if (key.startsWith('#') && Array.isArray(values) && values.length > CHUNK_SIZE) {
      needsChunking.tags[key] = true;
      delete baseFilter[key];
    }
  }

  // Helper function to process string array chunks
  const processStringChunks = async (filterType: 'ids' | 'authors' | string, values: string[]) => {
    const chunks = chunkArray(values, CHUNK_SIZE);

    for (const chunk of chunks) {
      const chunkFilter = { ...baseFilter };

      if (filterType === 'ids') {
        chunkFilter.ids = chunk;
      } else if (filterType === 'authors') {
        chunkFilter.authors = chunk;
      } else if (filterType.startsWith('#')) {
        chunkFilter[filterType] = chunk;
      }

      const query = buildQuery(chunkFilter);

      try {
        const result = await session.prepare(query.sql)
          .bind(...query.params)
          .all();

        for (const row of result.results) {
          allRows.set(row.id as string, row);
        }
      } catch (error) {
        console.error(`Error in chunk query: ${error}`);
      }
    }
  };

  // Helper function to process number array chunks
  const processNumberChunks = async (filterType: 'kinds', values: number[]) => {
    const chunks = chunkArray(values, CHUNK_SIZE);

    for (const chunk of chunks) {
      const chunkFilter = { ...baseFilter };
      chunkFilter.kinds = chunk;

      const query = buildQuery(chunkFilter);

      try {
        const result = await session.prepare(query.sql)
          .bind(...query.params)
          .all();

        for (const row of result.results) {
          allRows.set(row.id as string, row);
        }
      } catch (error) {
        console.error(`Error in chunk query: ${error}`);
      }
    }
  };

  // Process each filter type that needs chunking
  if (needsChunking.ids && filter.ids) {
    await processStringChunks('ids', filter.ids);
  }

  if (needsChunking.authors && filter.authors) {
    await processStringChunks('authors', filter.authors);
  }

  if (needsChunking.kinds && filter.kinds) {
    await processNumberChunks('kinds', filter.kinds);
  }

  // Process tag filters
  for (const [tagKey, _] of Object.entries(needsChunking.tags)) {
    const tagValues = filter[tagKey];
    if (Array.isArray(tagValues) && tagValues.every((v: any) => typeof v === 'string')) {
      await processStringChunks(tagKey, tagValues as string[]);
    }
  }

  // If nothing needed chunking, just run the query as-is
  if (!needsChunking.ids && !needsChunking.authors && !needsChunking.kinds && Object.keys(needsChunking.tags).length === 0) {
    const query = buildQuery(filter);

    try {
      const result = await session.prepare(query.sql)
        .bind(...query.params)
        .all();

      for (const row of result.results) {
        allRows.set(row.id as string, row);
      }
    } catch (error) {
      console.error(`Error in query: ${error}`);
    }
  }

  // Build events from collected rows
  const events = Array.from(allRows.values()).map(row => ({
    id: row.id as string,
    pubkey: row.pubkey as string,
    created_at: row.created_at as number,
    kind: row.kind as number,
    tags: JSON.parse(row.tags as string),
    content: row.content as string,
    sig: row.sig as string
  }));
  console.log(`Found ${events.length} events (chunked)`);

  return { events };
}
