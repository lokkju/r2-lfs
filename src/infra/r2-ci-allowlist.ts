import type { CiAllowlist } from "../app/ports.ts";
import { parseAllowlist } from "../domain/allowlist.ts";
import type { Repo } from "../domain/repo.ts";
import { ciAllowlistKey } from "../shared/contract.ts";

const TTL_MS = 60_000;
const cache = new Map<string, { oids: ReadonlySet<string>; expires: number }>();

export function clearCiAllowlistCache(): void {
  cache.clear();
}

/** Reads `_allowlist/{owner}/{repo}.txt`. Missing or malformed means an empty list. */
export class R2CiAllowlist implements CiAllowlist {
  private readonly bucket: R2Bucket;

  constructor(bucket: R2Bucket) {
    this.bucket = bucket;
  }

  async allows(repo: Repo, oid: string): Promise<boolean> {
    const key = ciAllowlistKey(repo.owner, repo.name);
    const hit = cache.get(key);
    if (hit && hit.expires > Date.now()) return hit.oids.has(oid);
    const text = await this.bucket.get(key).then((object) => object?.text());
    const oids = (text === undefined ? undefined : parseAllowlist(text)) ?? new Set<string>();
    cache.set(key, { oids, expires: Date.now() + TTL_MS });
    return oids.has(oid);
  }
}
