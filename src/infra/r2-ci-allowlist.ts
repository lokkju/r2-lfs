import type { CiAllowlist } from "../app/ports.ts";
import { parseAllowlist } from "../domain/allowlist.ts";
import type { Repo } from "../domain/repo.ts";
import { ciAllowlistKey } from "../shared/contract.ts";

const TTL_MS = 60_000;
// The read itself is cached, not only its result, so a batch's concurrent checks (up to 100)
// after the entry expires share one R2 read and one parse instead of each starting its own.
const cache = new Map<string, { oids: Promise<ReadonlySet<string>>; expires: number }>();

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
    if (hit && hit.expires > Date.now()) return (await hit.oids).has(oid);
    const oids = this.read(key);
    const entry = { oids, expires: Date.now() + TTL_MS };
    cache.set(key, entry);
    // A failed read is not cached: the next check reads again.
    oids.catch(() => {
      if (cache.get(key) === entry) cache.delete(key);
    });
    return (await oids).has(oid);
  }

  private async read(key: string): Promise<ReadonlySet<string>> {
    const text = await this.bucket.get(key).then((object) => object?.text());
    return (text === undefined ? undefined : parseAllowlist(text)) ?? new Set<string>();
  }
}
