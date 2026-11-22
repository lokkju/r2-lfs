import { afterEach, describe, expect, it, vi } from "vitest";

import type { PresignCredentials } from "../../src/domain/config.ts";
import { clearPresignClients, PresignedLinks, presignUrl } from "../../src/infra/transfer-links.ts";

const creds: PresignCredentials = { accountId: "acct", bucketName: "b", accessKeyId: "AKID", secretAccessKey: "secret" };
const authorize = async () => "Bearer t";
const key = (i: number) => `acme/app/${i.toString(16).padStart(64, "0")}`;

afterEach(() => {
  vi.restoreAllMocks();
  clearPresignClients();
});

// A batch presigns up to 100 objects. SigV4 derives the signing key with four HMACs per
// date, region and service; deriving it again for every URL costs about five HMACs a URL
// instead of one, enough CPU to run a 100-object batch past the Free plan's 10 ms.
describe("presigning cost", () => {
  it("derives the signing key once for a 100-object batch", async () => {
    const sign = vi.spyOn(crypto.subtle, "sign");
    const links = new PresignedLinks(creds, "https://lfs.example.com/acme/app", authorize);
    await Promise.all(Array.from({ length: 100 }, (_, i) => links.download(key(i))));
    // One HMAC per URL, plus at most one key derivation.
    expect(sign.mock.calls.length).toBeLessThanOrEqual(100 + 4);
  });

  it("reuses the signing key across batches with the same credentials", async () => {
    await presignUrl(creds, key(0), "GET");
    const sign = vi.spyOn(crypto.subtle, "sign");
    const links = new PresignedLinks(creds, "https://lfs.example.com/acme/app", authorize);
    await links.download(key(1));
    await links.upload(key(2));
    expect(sign.mock.calls.length).toBe(2);
  });

  it("signs with the credentials it was given, not a cached client's", async () => {
    const a = new URL(await presignUrl(creds, key(0), "GET"));
    const b = new URL(await presignUrl({ ...creds, accessKeyId: "OTHER", secretAccessKey: "other" }, key(0), "GET"));
    expect(a.searchParams.get("X-Amz-Credential")).toMatch(/^AKID\//);
    expect(b.searchParams.get("X-Amz-Credential")).toMatch(/^OTHER\//);
    expect(a.searchParams.get("X-Amz-Signature")).not.toBe(b.searchParams.get("X-Amz-Signature"));
  });
});
