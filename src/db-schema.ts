/** Database initialization version gate. Base-table creation is not proof that migrations ran. */
export function isDatabaseSchemaCurrent(initializedValue: unknown, schemaVersionValue: unknown): boolean {
  const version = Number(schemaVersionValue ?? 0);
  return initializedValue === "1" && Number.isFinite(version) && version >= 6;
}
