import { AwsClient } from "aws4fetch";

import type { Action, TransferLinks } from "../app/ports.ts";
import type { PresignCredentials } from "../domain/config.ts";
import { ACTION_TTL_SECONDS } from "../shared/contract.ts";

export const PRESIGN_EXPIRES_SECONDS = 3600;

/**
 * One AwsClient per credential pair for the life of the isolate. aws4fetch caches the SigV4
 * signing key on the client, so a shared client derives it once a day instead of with four
 * HMACs on every URL. A batch presigns up to 100 URLs at once, and deriving the key for each
 * one cost five times the HMACs, enough CPU to put a batch at risk of the Worker's CPU limit,
 * which Cloudflare answers with a 503.
 */
interface PresignClient {
  client: AwsClient;
  /** The UTC day (YYYYMMDD) whose signing key `ready` derives or derived. */
  day: string;
  /** The day's first signature. aws4fetch caches the key only once it resolves, so concurrent signatures wait for it. */
  ready: Promise<unknown>;
}

const clients = new Map<string, PresignClient>();

/** For tests: forget every cached client and signing key. */
export function clearPresignClients(): void {
  clients.clear();
}

export async function presignUrl(
  creds: PresignCredentials,
  key: string,
  method: "GET" | "PUT",
  expiresIn = PRESIGN_EXPIRES_SECONDS,
): Promise<string> {
  const url = new URL(`https://${creds.accountId}.r2.cloudflarestorage.com/${creds.bucketName}/${key}`);
  url.searchParams.set("X-Amz-Expires", String(expiresIn));
  const day = new Date().toISOString().slice(0, 10).replaceAll("-", "");
  const id = `${creds.accessKeyId}\n${creds.secretAccessKey}`;
  const entry = clients.get(id);
  if (entry?.day !== day) {
    const client =
      entry?.client ??
      new AwsClient({ accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, service: "s3", region: "auto" });
    const signed = sign(client, url, method);
    const fresh: PresignClient = { client, day, ready: signed };
    clients.set(id, fresh);
    // A failed first signature must not leave every later one waiting on it.
    signed.catch(() => {
      if (clients.get(id) === fresh) clients.delete(id);
    });
    return (await signed).url;
  }
  await entry.ready.catch(() => undefined);
  return (await sign(entry.client, url, method)).url;
}

function sign(client: AwsClient, url: URL, method: "GET" | "PUT"): Promise<Request> {
  return client.sign(new Request(url, { method }), { aws: { signQuery: true } });
}

/** Makes the Authorization header of an action: a token for this object's transfer only. */
export type ActionAuthorization = (oid: string, permission: "read" | "write") => Promise<string>;

/** Clients talk to R2 directly; only verification and multipart uploads come back to the Worker. */
export class PresignedLinks implements TransferLinks {
  readonly presigned = true;
  private readonly creds: PresignCredentials;
  private readonly baseUrl: string;
  private readonly authorize: ActionAuthorization;

  constructor(creds: PresignCredentials, baseUrl: string, authorize: ActionAuthorization) {
    this.creds = creds;
    this.baseUrl = baseUrl;
    this.authorize = authorize;
  }

  async download(key: string): Promise<Action> {
    return { href: await presignUrl(this.creds, key, "GET"), expires_in: PRESIGN_EXPIRES_SECONDS };
  }

  async upload(key: string): Promise<Action> {
    return { href: await presignUrl(this.creds, key, "PUT"), expires_in: PRESIGN_EXPIRES_SECONDS };
  }

  async verify(oid: string): Promise<Action> {
    return workerAction(`${this.baseUrl}/objects/verify`, await this.authorize(oid, "write"));
  }

  async multipart(oid: string): Promise<Action> {
    return workerAction(`${this.baseUrl}/objects/${oid}/multipart`, await this.authorize(oid, "write"));
  }
}

function workerAction(href: string, authorization: string): Action {
  return { href, header: { Authorization: authorization }, expires_in: ACTION_TTL_SECONDS };
}

/** Transfers stream through the Worker, each with a token for that object alone. */
export class ProxyLinks implements TransferLinks {
  readonly presigned = false;
  private readonly baseUrl: string;
  private readonly authorize: ActionAuthorization;

  constructor(baseUrl: string, authorize: ActionAuthorization) {
    this.baseUrl = baseUrl;
    this.authorize = authorize;
  }

  async download(_key: string, oid: string): Promise<Action> {
    return workerAction(`${this.baseUrl}/objects/${oid}`, await this.authorize(oid, "read"));
  }

  async upload(_key: string, oid: string): Promise<Action> {
    return workerAction(`${this.baseUrl}/objects/${oid}`, await this.authorize(oid, "write"));
  }

  async verify(oid: string): Promise<Action> {
    return workerAction(`${this.baseUrl}/objects/verify`, await this.authorize(oid, "write"));
  }

  async multipart(oid: string): Promise<Action> {
    return workerAction(`${this.baseUrl}/objects/${oid}/multipart`, await this.authorize(oid, "write"));
  }
}
