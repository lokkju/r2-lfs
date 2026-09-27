/** Whether `ref` matches a pattern in which `*` stands for any run of characters, slashes included. */
export function refMatches(pattern: string, ref: string): boolean {
  const source = pattern
    .split("*")
    .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  return new RegExp(`^${source}$`).test(ref);
}

/** No patterns keeps upstream behaviour: any ref. With patterns, a missing ref is refused. */
export function refAllowed(patterns: readonly string[], ref: string | undefined): boolean {
  if (patterns.length === 0) return true;
  return ref !== undefined && patterns.some((pattern) => refMatches(pattern, ref));
}
