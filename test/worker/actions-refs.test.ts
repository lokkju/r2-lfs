import { beforeEach, describe, expect, it } from "vitest";

import { refAllowed } from "../../src/domain/refs.ts";
import type { Env } from "../../src/env.ts";
import { handle } from "../../src/http/handler.ts";
import { clearHostCache, type Fetcher } from "../../src/infra/host-permissions.ts";
import { clearJwtKeysCache } from "../../src/infra/jwt.ts";
import { basic, envWith } from "./helpers.ts";
import { signingKey } from "./jwt-helpers.ts";

const ISSUER = "https://token.actions.githubusercontent.com";
const now = () => Math.floor(Date.now() / 1000);
const claims = (over: Record<string, unknown> = {}) => ({
  iss: ISSUER,
  aud: "r2-lfs",
  exp: now() + 300,
  repository: "acme/assets",
  actor: "octocat",
  ref: "refs/heads/main",
  ...over,
});
const makeEnv = envWith({ AUTH_MODE: "github", TRANSFER_MODE: "proxy", ACTIONS_OIDC: "read" });

async function setup() {
  const key = await signingKey("gh1");
  const fetcher: Fetcher = async (input) => {
    if (String(input) === `${ISSUER}/.well-known/jwks`) return Response.json({ keys: [key.jwk] });
    throw new Error(`unexpected request to ${String(input)}`);
  };
  const batch = (e: Env, token: string) =>
    handle(
      new Request("https://lfs.example.com/acme/assets/objects/batch", {
        method: "POST",
        headers: { Authorization: basic(token, "oidc"), "Content-Type": "application/vnd.git-lfs+json" },
        body: JSON.stringify({ operation: "download", objects: [] }),
      }),
      e,
      { fetch: fetcher },
    );
  return { key, batch };
}

beforeEach(() => {
  clearJwtKeysCache();
  clearHostCache();
});

describe("refAllowed", () => {
  it("allows any ref when no pattern is configured", () => {
    expect(refAllowed([], undefined)).toBe(true);
    expect(refAllowed([], "refs/tags/v1")).toBe(true);
  });
  it("matches * across any characters, including slashes", () => {
    const patterns = ["refs/heads/*", "refs/pull/*/merge"];
    expect(refAllowed(patterns, "refs/heads/main")).toBe(true);
    expect(refAllowed(patterns, "refs/heads/feature/x")).toBe(true);
    expect(refAllowed(patterns, "refs/pull/12/merge")).toBe(true);
    expect(refAllowed(patterns, "refs/tags/v1")).toBe(false);
    expect(refAllowed(patterns, "refs/pull/12/head")).toBe(false);
  });
  it("refuses a missing ref once patterns are configured", () => {
    expect(refAllowed(["refs/heads/*"], undefined)).toBe(false);
  });
  it("treats regex metacharacters in patterns literally", () => {
    expect(refAllowed(["refs/heads/v1.0"], "refs/heads/v1x0")).toBe(false);
  });
});

describe("ACTIONS_OIDC_REFS", () => {
  const refs = { ACTIONS_OIDC_REFS: "refs/heads/*,refs/pull/*/merge" };

  it("accepts a workflow on an allowed ref", async () => {
    const { key, batch } = await setup();
    expect((await batch(makeEnv(refs), await key.sign(claims()))).status).toBe(200);
    expect((await batch(makeEnv(refs), await key.sign(claims({ ref: "refs/pull/7/merge" })))).status).toBe(200);
  });

  it("refuses a workflow on a ref no pattern matches", async () => {
    const { key, batch } = await setup();
    const res = await batch(makeEnv(refs), await key.sign(claims({ ref: "refs/tags/v1" })));
    expect(res.status).toBe(403);
    expect(await res.text()).toContain("refs/tags/v1");
  });

  it("refuses a token without a ref claim", async () => {
    const { key, batch } = await setup();
    expect((await batch(makeEnv(refs), await key.sign(claims({ ref: undefined })))).status).toBe(403);
  });

  it("keeps upstream behaviour when unset", async () => {
    const { key, batch } = await setup();
    expect((await batch(makeEnv(), await key.sign(claims({ ref: "refs/tags/v1" })))).status).toBe(200);
  });

  it("rejects a pattern that does not start with refs/", async () => {
    const res = await handle(new Request("https://lfs.example.com/_r2-lfs/info"), makeEnv({ ACTIONS_OIDC_REFS: "main" }), { fetch });
    expect(await res.text()).toContain("ACTIONS_OIDC_REFS");
  });
});
