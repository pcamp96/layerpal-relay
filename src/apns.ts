// Minimal APNs client for Workers: ES256 provider tokens via WebCrypto.
// Workers negotiate HTTP/2 with Apple in production; `wrangler dev` can't
// reach APNs (cloudflare/workerd#4841), so test against a deployed Worker.

export type ApnsEnvironment = "sandbox" | "production";

export interface ApnsKey {
  teamId: string;
  keyId: string;
  p8: string;
}

export interface ApnsResult {
  ok: boolean;
  status: number;
  reason: string;
}

const HOSTS: Record<ApnsEnvironment, string> = {
  production: "https://api.push.apple.com",
  sandbox: "https://api.sandbox.push.apple.com",
};

const DEAD_REASONS = new Set(["BadDeviceToken", "Unregistered", "DeviceTokenNotForTopic", "ExpiredToken"]);

export function isDeadToken(r: ApnsResult): boolean {
  return r.status === 410 || DEAD_REASONS.has(r.reason);
}

// Apple rejects tokens older than an hour and throttles refreshes under 20 minutes.
const TOKEN_TTL_MS = 50 * 60 * 1000;
const tokenCache = new Map<string, { jwt: string; at: number }>();
const keyCache = new Map<string, CryptoKey>();

function b64url(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (const b of arr) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlJson(obj: unknown): string {
  return b64url(new TextEncoder().encode(JSON.stringify(obj)));
}

/** Accepts the .p8 with or without armor/newlines (secrets often lose them). */
export function p8ToDer(p8: string): Uint8Array {
  const body = p8
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");
  const bin = atob(body);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function signingKey(key: ApnsKey): Promise<CryptoKey> {
  let k = keyCache.get(key.keyId);
  if (!k) {
    k = await crypto.subtle.importKey("pkcs8", p8ToDer(key.p8), { name: "ECDSA", namedCurve: "P-256" }, false, [
      "sign",
    ]);
    keyCache.set(key.keyId, k);
  }
  return k;
}

export async function providerToken(key: ApnsKey, now = Date.now()): Promise<string> {
  const cached = tokenCache.get(key.keyId);
  if (cached && now - cached.at < TOKEN_TTL_MS) return cached.jwt;
  const head = b64urlJson({ alg: "ES256", kid: key.keyId });
  const claims = b64urlJson({ iss: key.teamId, iat: Math.floor(now / 1000) });
  const input = `${head}.${claims}`;
  // WebCrypto ECDSA returns raw r||s, which is exactly JWS ES256 format.
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    await signingKey(key),
    new TextEncoder().encode(input),
  );
  const jwt = `${input}.${b64url(sig)}`;
  tokenCache.set(key.keyId, { jwt, at: now });
  return jwt;
}

export interface SendOptions {
  environment: ApnsEnvironment;
  bundleId: string;
  pushType?: "alert" | "liveactivity";
  priority?: 5 | 10;
  collapseId?: string;
}

export async function sendPush(key: ApnsKey, deviceToken: string, payload: unknown, opts: SendOptions): Promise<ApnsResult> {
  const pushType = opts.pushType ?? "alert";
  const topic = pushType === "liveactivity" ? `${opts.bundleId}.push-type.liveactivity` : opts.bundleId;
  const headers: Record<string, string> = {
    authorization: `bearer ${await providerToken(key)}`,
    "apns-topic": topic,
    "apns-push-type": pushType,
    "apns-priority": String(opts.priority ?? 10),
    "content-type": "application/json",
  };
  if (opts.collapseId) headers["apns-collapse-id"] = opts.collapseId.slice(0, 64);
  const res = await fetch(`${HOSTS[opts.environment]}/3/device/${deviceToken}`, {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
  });
  if (res.status === 200) return { ok: true, status: 200, reason: "" };
  let reason = "";
  try {
    reason = ((await res.json()) as { reason?: string }).reason ?? "";
  } catch {
    reason = (await res.text().catch(() => "")).slice(0, 200);
  }
  return { ok: false, status: res.status, reason };
}
