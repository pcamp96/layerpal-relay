// AES-GCM for the read-only Bambuddy keys the relay polls with.
// POLL_KEY_SECRET is 32 random bytes (base64) stored as a Worker secret.

const keyCache = new Map<string, CryptoKey>();

async function aesKey(secretB64: string): Promise<CryptoKey> {
  let k = keyCache.get(secretB64);
  if (!k) {
    const raw = Uint8Array.from(atob(secretB64), (c) => c.charCodeAt(0));
    k = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
    keyCache.set(secretB64, k);
  }
  return k;
}

const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export async function seal(secretB64: string, plaintext: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesKey(secretB64), new TextEncoder().encode(plaintext)),
  );
  return `${b64(iv)}:${b64(ct)}`;
}

export async function open(secretB64: string, sealed: string): Promise<string> {
  const [iv, ct] = sealed.split(":");
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, await aesKey(secretB64), unb64(ct));
  return new TextDecoder().decode(pt);
}
