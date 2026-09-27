import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { parseAllowlist } from "../../src/domain/allowlist.ts";
import type { Env } from "../../src/env.ts";
import { handle } from "../../src/http/handler.ts";
import { clearHostCache, type Fetcher } from "../../src/infra/host-permissions.ts";
import { clearJwtKeysCache } from "../../src/infra/jwt.ts";
import { clearCiAllowlistCache } from "../../src/infra/r2-ci-allowlist.ts";
import { clearRepositoryIdentitiesCache } from "../../src/infra/r2-repository-identities.ts";
import { HmacSessionTokens } from "../../src/infra/session-tokens.ts";
import { basic, blob, envWith } from "./helpers.ts";
import { signingKey } from "./jwt-helpers.ts";

const ISSUER = "https://token.actions.githubusercontent.com";
const OPERATOR = "operator-token-0123456789abcdef";
const now = () => Math.floor(Date.now() / 1000);
const makeEnv = envWith({
  AUTH_MODE: "token",
  AUTH_TOKENS: `acme/*:rw:${OPERATOR}`,
  TRANSFER_MODE: "proxy",
  ACTIONS_OIDC: "read",
  ACTIONS_OIDC_ALLOWLIST: "on",
});

let counter = 0;

async function setup() {
  const repo = `books-${counter++}-${Date.now()}`;
  const key = await signingKey("gh1");
  const fetcher: Fetcher = async (input) => {
    if (String(input) === `${ISSUER}/.well-known/jwks`) return Response.json({ keys: [key.jwk] });
    throw new Error(`unexpected request to ${String(input)}`);
  };
  const oidc = await key.sign({
    iss: ISSUER,
    aud: "r2-lfs",
    exp: now() + 300,
    repository: `acme/${repo}`,
    actor: "ci",
    ref: "refs/heads/main",
  });
  const pub = await blob();
  const secret = await blob();
  for (const b of [pub, secret]) await env.BUCKET.put(`acme/${repo}/${b.oid}`, b.data);
  const batch = (e: Env, password: string, oids: { oid: string; size: number }[]) =>
    handle(
      new Request(`https://lfs.example.com/acme/${repo}/objects/batch`, {
        method: "POST",
        headers: { Authorization: basic(password, "oidc"), "Content-Type": "application/vnd.git-lfs+json" },
        body: JSON.stringify({ operation: "download", objects: oids }),
      }),
      e,
      { fetch: fetcher },
    );
  const get = (e: Env, password: string, oid: string) =>
    handle(new Request(`https://lfs.example.com/acme/${repo}/objects/${oid}`, { headers: { Authorization: basic(password, "oidc") } }), e, {
      fetch: fetcher,
    });
  const setList = (text: string) => env.BUCKET.put(`_allowlist/acme/${repo}.txt`, text);
  const openSession = (e: Env, password: string) =>
    handle(
      new Request(`https://lfs.example.com/acme/${repo}/r2-lfs/session`, {
        method: "POST",
        headers: { Authorization: basic(password, "oidc") },
      }),
      e,
      { fetch: fetcher },
    );
  return { repo, oidc, pub, secret, batch, get, setList, openSession, fetcher };
}

type BatchBody = {
  objects: { oid: string; actions?: { download?: { href: string; header?: Record<string, string> } }; error?: { code: number } }[];
};

beforeEach(() => {
  clearJwtKeysCache();
  clearHostCache();
  clearCiAllowlistCache();
  clearRepositoryIdentitiesCache();
});

describe("parseAllowlist", () => {
  const a = "a".repeat(64);
  const b = "b".repeat(64);
  it("reads one lowercase 64-hex oid per line", () => {
    expect(parseAllowlist(`${a}\n${b}\n`)).toEqual(new Set([a, b]));
  });
  it("reads an empty file as an empty list", () => {
    expect(parseAllowlist("")).toEqual(new Set());
  });
  it("rejects a malformed line, an uppercase oid, a comment or a blank line", () => {
    for (const text of [`${a}\nnot-an-oid\n`, `${a.toUpperCase()}\n`, `# c\n${a}\n`, `${a}\n\n${b}\n`]) {
      expect(parseAllowlist(text)).toBeUndefined();
    }
  });
});

describe("ACTIONS_OIDC_ALLOWLIST", () => {
  it("lets CI download a listed object and refuses an unlisted one in the same batch", async () => {
    const s = await setup();
    await s.setList(`${s.pub.oid}\n`);
    const res = await s.batch(
      makeEnv(),
      s.oidc,
      [s.pub, s.secret].map(({ oid, size }) => ({ oid, size })),
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as BatchBody;
    const byOid = new Map(body.objects.map((o) => [o.oid, o]));
    expect(byOid.get(s.pub.oid)?.actions).toBeDefined();
    expect(byOid.get(s.secret.oid)?.error?.code).toBe(403);
    expect(byOid.get(s.secret.oid)?.actions).toBeUndefined();
  });

  it("refuses a direct GET of an unlisted object with the OIDC credential", async () => {
    const s = await setup();
    await s.setList(`${s.pub.oid}\n`);
    expect((await s.get(makeEnv(), s.oidc, s.secret.oid)).status).toBe(403);
    expect((await s.get(makeEnv(), s.oidc, s.pub.oid)).status).toBe(200);
  });

  it("refuses everything to CI when the list is missing", async () => {
    const s = await setup();
    const body = (await (await s.batch(makeEnv(), s.oidc, [{ oid: s.pub.oid, size: s.pub.size }])).json()) as BatchBody;
    expect(body.objects[0]?.error?.code).toBe(403);
  });

  it("refuses everything to CI when the list is malformed", async () => {
    const s = await setup();
    await s.setList(`${s.pub.oid}\nnot-an-oid\n`);
    const body = (await (await s.batch(makeEnv(), s.oidc, [{ oid: s.pub.oid, size: s.pub.size }])).json()) as BatchBody;
    expect(body.objects[0]?.error?.code).toBe(403);
  });

  it("never lets CI write, even for a listed object", async () => {
    const s = await setup();
    await s.setList(`${s.pub.oid}\n`);
    const res = await handle(
      new Request(`https://lfs.example.com/acme/${s.repo}/objects/batch`, {
        method: "POST",
        headers: { Authorization: basic(s.oidc, "oidc"), "Content-Type": "application/vnd.git-lfs+json" },
        body: JSON.stringify({ operation: "upload", objects: [{ oid: s.pub.oid, size: s.pub.size }] }),
      }),
      makeEnv(),
      { fetch: s.fetcher },
    );
    expect(res.status).toBe(403);
  });

  it("refuses a token from another repository", async () => {
    const s = await setup();
    await s.setList(`${s.pub.oid}\n`);
    const key = await signingKey("gh1");
    const fetcher: Fetcher = async () => Response.json({ keys: [key.jwk] });
    const foreign = await key.sign({
      iss: ISSUER,
      aud: "r2-lfs",
      exp: now() + 300,
      repository: "acme/other",
      actor: "ci",
      ref: "refs/heads/main",
    });
    const res = await handle(
      new Request(`https://lfs.example.com/acme/${s.repo}/objects/batch`, {
        method: "POST",
        headers: { Authorization: basic(foreign, "oidc"), "Content-Type": "application/vnd.git-lfs+json" },
        body: JSON.stringify({ operation: "download", objects: [{ oid: s.pub.oid, size: s.pub.size }] }),
      }),
      makeEnv(),
      { fetch: fetcher },
    );
    expect(res.status).toBe(404);
  });

  it("does not restrict the operator token", async () => {
    const s = await setup();
    await s.setList(`${s.pub.oid}\n`);
    const body = (await (await s.batch(makeEnv(), OPERATOR, [{ oid: s.secret.oid, size: s.secret.size }])).json()) as BatchBody;
    expect(body.objects[0]?.actions).toBeDefined();
  });

  it("does not restrict CI when the setting is off", async () => {
    const s = await setup();
    const body = (await (
      await s.batch(makeEnv({ ACTIONS_OIDC_ALLOWLIST: "off" }), s.oidc, [{ oid: s.secret.oid, size: s.secret.size }])
    ).json()) as BatchBody;
    expect(body.objects[0]?.actions).toBeDefined();
  });
});

describe("tokens an Actions caller can obtain", () => {
  it("refuses to open a session for an Actions credential", async () => {
    const s = await setup();
    await s.setList(`${s.pub.oid}\n`);
    expect((await s.openSession(makeEnv(), s.oidc)).status).toBe(403);
  });

  it("still opens a session for the operator token", async () => {
    const s = await setup();
    expect((await s.openSession(makeEnv(), OPERATOR)).status).toBe(200);
  });

  it("keeps a session token minted for an Actions caller limited to the list", async () => {
    const s = await setup();
    await s.setList(`${s.pub.oid}\n`);
    const token = await new HmacSessionTokens(env.BUCKET).mint({
      repo: `acme/${s.repo}`.toLowerCase(),
      permission: "read",
      expires: now() + 600,
      principal: "actions",
    });
    expect((await s.get(makeEnv(), token, s.secret.oid)).status).toBe(403);
    expect((await s.get(makeEnv(), token, s.pub.oid)).status).toBe(200);
    const body = (await (await s.batch(makeEnv(), token, [{ oid: s.secret.oid, size: s.secret.size }])).json()) as BatchBody;
    expect(body.objects[0]?.error?.code).toBe(403);
  });

  it("tags the transfer action token it issues to CI, so a delisted object is refused", async () => {
    const s = await setup();
    await s.setList(`${s.pub.oid}\n`);
    const body = (await (await s.batch(makeEnv(), s.oidc, [{ oid: s.pub.oid, size: s.pub.size }])).json()) as BatchBody;
    const action = body.objects[0]?.actions?.download;
    expect(action).toBeDefined();
    const fetchAction = () => handle(new Request(action!.href, { headers: action!.header ?? {} }), makeEnv(), { fetch: s.fetcher });
    expect((await fetchAction()).status).toBe(200);
    await s.setList("");
    clearCiAllowlistCache();
    expect((await fetchAction()).status).toBe(403);
  });
});
