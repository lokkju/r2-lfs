const OID_LINE = /^[0-9a-f]{64}$/;

/**
 * Parses a CI allow list: one lowercase 64-hex object id per line, newline-terminated.
 * Any line that is not an oid makes the whole list invalid, so a damaged list refuses everything.
 */
export function parseAllowlist(text: string): ReadonlySet<string> | undefined {
  if (text === "") return new Set();
  if (!text.endsWith("\n")) return undefined;
  const lines = text.slice(0, -1).split("\n");
  if (!lines.every((line) => OID_LINE.test(line))) return undefined;
  return new Set(lines);
}
