// LayerPal push relay (Cloudflare Worker).
//
// Each phone registers here and gets a private webhook URL that goes into
// its Bambuddy as a stock "Webhook" notification provider. Bambuddy posts
// events to it; the relay turns them into APNs alerts.
//
// The Lock Screen card (one Live Activity for all active prints) is kept
// current by a once-a-minute check of the phone's Bambuddy, using a separate
// read-only API key the app hands over at setup (AES-GCM encrypted at rest).
// Webhooks still trigger an immediate refresh.

import { type ApnsEnvironment, type ApnsKey, isDeadToken, sendPush } from "./apns";
import { open, seal } from "./crypto";
import {
  ACTIVITY_TYPE,
  type BambuddyWebhook,
  type PrintRow,
  type PrinterLite,
  type StatusLite,
  activityState,
  alertPayload,
  isActive,
  printUpdate,
  rowsFromStatuses,
  stateKey,
  wantsAlert,
} from "./events";

export interface Env {
  DB: D1Database;
  APNS_TEAM_ID: string;
  APNS_BUNDLE_ID: string;
  APNS_SANDBOX_KEY_ID?: string;
  APNS_SANDBOX_P8?: string;
  APNS_PRODUCTION_KEY_ID?: string;
  APNS_PRODUCTION_P8?: string;
  POLL_KEY_SECRET?: string;
}

interface DeviceRow {
  relay_token: string;
  device_token: string;
  environment: ApnsEnvironment;
  start_token: string | null;
  server_url?: string | null;
  poll_key?: string | null;
  last_state?: string | null;
  last_push_at?: number | null;
}

const HEX = /^[0-9a-f]{16,200}$/i;
const STALE_AFTER_S = 15 * 60;
const DISMISS_AFTER_S = 15 * 60;
/** Push at least this often while printing, even with no visible change. */
const HEARTBEAT_S = 5 * 60;
const MAX_BODY = 512 * 1024; // Bambuddy may include a base64 image we ignore
/** Cron fan-out cap per minute (subrequest budget). */
const MAX_POLLS_PER_RUN = 20;

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });

function apnsKey(env: Env, environment: ApnsEnvironment): ApnsKey | null {
  const keyId = environment === "sandbox" ? env.APNS_SANDBOX_KEY_ID : env.APNS_PRODUCTION_KEY_ID;
  const p8 = environment === "sandbox" ? env.APNS_SANDBOX_P8 : env.APNS_PRODUCTION_P8;
  return keyId && p8 && env.APNS_TEAM_ID ? { teamId: env.APNS_TEAM_ID, keyId, p8 } : null;
}

function newRelayToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function readJson<T>(req: Request): Promise<T | null> {
  const len = Number(req.headers.get("content-length") ?? "0");
  if (len > MAX_BODY) return null;
  try {
    return (await req.json()) as T;
  } catch {
    return null;
  }
}

const DEVICE_COLS = "relay_token, device_token, environment, start_token, server_url, poll_key, last_state, last_push_at";
const PRINT_COLS = "printer, phase, progress, finish_at, job, updated_at, layer, total_layers";

async function getDevice(env: Env, relayToken: string): Promise<DeviceRow | null> {
  return env.DB.prepare(`SELECT ${DEVICE_COLS} FROM devices WHERE relay_token = ?`).bind(relayToken).first<DeviceRow>();
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const parts = url.pathname.split("/").filter(Boolean);

    if (req.method === "GET" && url.pathname === "/health") {
      return json({
        ok: true,
        sandbox: !!apnsKey(env, "sandbox"),
        production: !!apnsKey(env, "production"),
        polling: !!env.POLL_KEY_SECRET,
      });
    }
    if (req.method === "POST" && url.pathname === "/v1/register") return register(req, env, url);
    if (req.method === "POST" && url.pathname === "/v1/activity") return registerActivity(req, env);
    if (req.method === "POST" && url.pathname === "/v1/poll-credentials") return setPollCredentials(req, env);
    if (req.method === "DELETE" && parts[0] === "v1" && parts[1] === "devices" && parts[2]) {
      await deleteDevice(env, parts[2]);
      return new Response(null, { status: 204 });
    }
    if (req.method === "POST" && parts[0] === "v1" && parts[1] === "hook" && parts[2]) return hook(req, env, parts[2]);
    return json({ error: "not found" }, 404);
  },

  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(pollAll(env));
  },
};

// MARK: Registration

async function deleteDevice(env: Env, relayToken: string): Promise<void> {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM activities WHERE relay_token = ?").bind(relayToken),
    env.DB.prepare("DELETE FROM prints WHERE relay_token = ?").bind(relayToken),
    env.DB.prepare("DELETE FROM devices WHERE relay_token = ?").bind(relayToken),
  ]);
}

async function register(req: Request, env: Env, url: URL): Promise<Response> {
  const body = await readJson<{
    device_token?: string;
    environment?: string;
    push_to_start_token?: string | null;
    relay_token?: string;
    live_activities?: boolean;
  }>(req);
  if (!body || !body.device_token || !HEX.test(body.device_token)) return json({ error: "bad device_token" }, 400);
  const environment = body.environment === "sandbox" ? "sandbox" : "production";
  const start = body.push_to_start_token && HEX.test(body.push_to_start_token) ? body.push_to_start_token : null;
  const now = Date.now();

  let token = body.relay_token && /^[0-9a-f]{48}$/.test(body.relay_token) ? body.relay_token : null;
  if (token && !(await getDevice(env, token))) token = null;
  if (token) {
    await env.DB.prepare(
      "UPDATE devices SET device_token = ?, environment = ?, start_token = COALESCE(?, start_token), updated_at = ? WHERE relay_token = ?",
    )
      .bind(body.device_token, environment, start, now, token)
      .run();
  } else {
    token = newRelayToken();
    await env.DB.prepare(
      "INSERT INTO devices (relay_token, device_token, environment, start_token, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
      .bind(token, body.device_token, environment, start, now, now)
      .run();
  }
  if (body.live_activities === false) {
    // User switched the Lock Screen card off: forget how to start one and stop refreshing.
    await env.DB.batch([
      env.DB.prepare("UPDATE devices SET start_token = NULL, last_state = NULL WHERE relay_token = ?").bind(token),
      env.DB.prepare("DELETE FROM activities WHERE relay_token = ?").bind(token),
      env.DB.prepare("DELETE FROM prints WHERE relay_token = ?").bind(token),
    ]);
  }
  const device = await getDevice(env, token);
  return json({
    relay_token: token,
    webhook_url: `${url.origin}/v1/hook/${token}`,
    push_ready: !!apnsKey(env, environment),
    polling: !!device?.poll_key,
  });
}

/** The app hands over its server URL + a read-only Bambuddy key for status polling. */
async function setPollCredentials(req: Request, env: Env): Promise<Response> {
  if (!env.POLL_KEY_SECRET) return json({ error: "polling not configured" }, 503);
  const body = await readJson<{ relay_token?: string; server_url?: string; api_key?: string }>(req);
  if (!body?.relay_token || !(await getDevice(env, body.relay_token))) return json({ error: "unknown device" }, 404);
  if (!body.server_url || !body.api_key) {
    await env.DB.prepare("UPDATE devices SET server_url = NULL, poll_key = NULL WHERE relay_token = ?").bind(body.relay_token).run();
    return new Response(null, { status: 204 });
  }
  let server: URL;
  try {
    server = new URL(body.server_url);
  } catch {
    return json({ error: "bad server_url" }, 400);
  }
  if (server.protocol !== "https:") return json({ error: "Bambuddy must be reachable over https for background updates" }, 400);
  const sealed = await seal(env.POLL_KEY_SECRET, body.api_key);
  const base = server.origin + server.pathname.replace(/\/?$/, "/");
  await env.DB.prepare("UPDATE devices SET server_url = ?, poll_key = ?, last_poll_error = NULL WHERE relay_token = ?")
    .bind(base, sealed, body.relay_token)
    .run();
  return new Response(null, { status: 204 });
}

async function registerActivity(req: Request, env: Env): Promise<Response> {
  const body = await readJson<{ relay_token?: string; push_token?: string }>(req);
  if (!body?.relay_token || !body.push_token || !HEX.test(body.push_token)) {
    return json({ error: "relay_token and push_token are required" }, 400);
  }
  if (!(await getDevice(env, body.relay_token))) return json({ error: "unknown device" }, 404);
  await env.DB.batch([
    // One all-prints card per phone: a new token replaces the old ones.
    env.DB.prepare("DELETE FROM activities WHERE relay_token = ? AND push_token != ?").bind(body.relay_token, body.push_token),
    env.DB.prepare(
      "INSERT INTO activities (push_token, relay_token, printer, created_at) VALUES (?, ?, '*', ?) ON CONFLICT(push_token) DO NOTHING",
    ).bind(body.push_token, body.relay_token, Date.now()),
    env.DB.prepare("UPDATE devices SET last_state = NULL WHERE relay_token = ?").bind(body.relay_token),
  ]);
  return new Response(null, { status: 204 });
}

// MARK: Webhooks

function upsertPrint(env: Env, relayToken: string, r: PrintRow): D1PreparedStatement {
  return env.DB.prepare(
    `INSERT INTO prints (relay_token, ${PRINT_COLS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ` +
      "ON CONFLICT(relay_token, printer) DO UPDATE SET phase = excluded.phase, progress = excluded.progress, " +
      // Keep the last known ETA / job / layers when an event doesn't carry them.
      "finish_at = CASE WHEN excluded.finish_at > 0 OR excluded.phase NOT IN ('printing','paused','preparing','error') " +
      "THEN excluded.finish_at ELSE prints.finish_at END, " +
      "job = CASE WHEN excluded.job != '' THEN excluded.job ELSE prints.job END, " +
      "layer = CASE WHEN excluded.layer > 0 THEN excluded.layer ELSE prints.layer END, " +
      "total_layers = CASE WHEN excluded.total_layers > 0 THEN excluded.total_layers ELSE prints.total_layers END, " +
      "updated_at = excluded.updated_at",
  ).bind(relayToken, r.printer, r.phase, r.progress, r.finish_at, r.job, r.updated_at, r.layer ?? 0, r.total_layers ?? 0);
}

async function hook(req: Request, env: Env, relayToken: string): Promise<Response> {
  const device = await getDevice(env, relayToken);
  if (!device) return json({ error: "unknown device" }, 404);
  const w = await readJson<BambuddyWebhook>(req);
  if (!w) return json({ error: "expected Bambuddy generic webhook JSON" }, 400);
  const key = apnsKey(env, device.environment);
  if (!key) return json({ error: `relay has no ${device.environment} APNs key yet` }, 503);

  const nowS = Math.floor(Date.now() / 1000);
  await env.DB.prepare("UPDATE devices SET last_hook_at = ? WHERE relay_token = ?").bind(Date.now(), relayToken).run();

  const results: string[] = [];
  const update = printUpdate(w, nowS);
  let started = false;
  if (update) {
    await upsertPrint(env, relayToken, update).run();
    const r = await syncActivity(env, key, device, nowS, { force: true, starter: update.printer });
    results.push(`activity:${r}`);
    started = r === "started";
  }
  // Start/progress normally only feed the card; if no card could be started, notify instead.
  if (wantsAlert(w.event) || (w.event === "print_start" && !started)) results.push(await alert(env, key, device, w));
  return json({ ok: true, results });
}

async function alert(env: Env, key: ApnsKey, device: DeviceRow, w: BambuddyWebhook): Promise<string> {
  const r = await sendPush(key, device.device_token, alertPayload(w), {
    environment: device.environment,
    bundleId: env.APNS_BUNDLE_ID,
  });
  if (isDeadToken(r)) {
    await deleteDevice(env, device.relay_token);
    return `alert:dead(${r.reason})`;
  }
  return r.ok ? "alert:sent" : `alert:failed(${r.status} ${r.reason})`;
}

// MARK: Polling

async function pollAll(env: Env): Promise<void> {
  if (!env.POLL_KEY_SECRET) return;
  // Phones that have a card running, or could start one.
  const { results: devices } = await env.DB.prepare(
    `SELECT ${DEVICE_COLS} FROM devices WHERE poll_key IS NOT NULL AND server_url IS NOT NULL ` +
      "AND (start_token IS NOT NULL OR EXISTS (SELECT 1 FROM activities a WHERE a.relay_token = devices.relay_token)) " +
      "ORDER BY COALESCE(last_push_at, 0) ASC LIMIT ?",
  )
    .bind(MAX_POLLS_PER_RUN)
    .all<DeviceRow>();
  await Promise.allSettled(devices.map((d) => pollDevice(env, d)));
}

async function pollDevice(env: Env, device: DeviceRow): Promise<string> {
  const key = apnsKey(env, device.environment);
  if (!key || !device.poll_key || !device.server_url || !env.POLL_KEY_SECRET) return "skip";
  const nowS = Math.floor(Date.now() / 1000);
  try {
    const apiKey = await open(env.POLL_KEY_SECRET, device.poll_key);
    const server = device.server_url;
    const get = async <T>(path: string): Promise<T> => {
      const res = await fetch(new URL(`api/v1/${path}`, server), {
        // "-" = the user's Bambuddy has login turned off.
        headers: apiKey === "-" ? { "User-Agent": "LayerPal-Relay/1.0" } : { "X-API-Key": apiKey, "User-Agent": "LayerPal-Relay/1.0" },
      });
      if (!res.ok) throw new Error(`${path} returned HTTP ${res.status}`);
      return (await res.json()) as T;
    };
    const printers = await get<PrinterLite[]>("printers/");
    const ids = printers.filter((p) => p.is_active !== false).map((p) => p.id);
    const statuses = ids.length ? await get<StatusLite[]>(`bulk/printer-statuses?ids=${ids.join(",")}`) : [];

    const { results: existingRows } = await env.DB.prepare(`SELECT ${PRINT_COLS} FROM prints WHERE relay_token = ?`)
      .bind(device.relay_token)
      .all<PrintRow>();
    const existing = new Map(existingRows.map((r) => [r.printer, r]));
    const rows = rowsFromStatuses(printers, statuses, existing, nowS);
    if (rows.length) await env.DB.batch(rows.map((r) => upsertPrint(env, device.relay_token, r)));
    await env.DB.prepare("UPDATE devices SET last_poll_error = NULL WHERE relay_token = ?").bind(device.relay_token).run();
    return await syncActivity(env, key, device, nowS, { force: false });
  } catch (e) {
    await env.DB.prepare("UPDATE devices SET last_poll_error = ? WHERE relay_token = ?")
      .bind(String(e).slice(0, 300), device.relay_token)
      .run();
    return `error:${e}`;
  }
}

// MARK: Card sync

/** Brings the phone's single all-prints card in line with the prints table. */
async function syncActivity(
  env: Env,
  key: ApnsKey,
  device: DeviceRow,
  nowS: number,
  opts: { force: boolean; starter?: string },
): Promise<string> {
  const { results: rows } = await env.DB.prepare(`SELECT ${PRINT_COLS} FROM prints WHERE relay_token = ?`)
    .bind(device.relay_token)
    .all<PrintRow>();
  const state = activityState(rows, nowS);
  const anyActive = state.prints.some((p) => isActive(p.phase));
  const changeKey = stateKey(state);
  const changed = changeKey !== device.last_state;
  const { results: tokens } = await env.DB.prepare("SELECT push_token FROM activities WHERE relay_token = ?")
    .bind(device.relay_token)
    .all<{ push_token: string }>();

  // Routine refreshes at priority 5 (Apple's budget-friendly lane); real changes at 10.
  const send = (token: string, aps: Record<string, unknown>) =>
    sendPush(
      key,
      token,
      { aps: { timestamp: nowS, "content-state": state, ...aps } },
      {
        environment: device.environment,
        bundleId: env.APNS_BUNDLE_ID,
        pushType: "liveactivity",
        priority: opts.force || changed ? 10 : 5,
      },
    );
  const remember = () =>
    env.DB.prepare("UPDATE devices SET last_state = ?, last_push_at = ? WHERE relay_token = ?")
      .bind(changeKey, nowS, device.relay_token)
      .run();

  if (tokens.length > 0) {
    if (anyActive) {
      if (!opts.force && !changed && nowS - (device.last_push_at ?? 0) < HEARTBEAT_S) return "unchanged";
      for (const t of tokens) {
        const r = await send(t.push_token, { event: "update", "stale-date": nowS + STALE_AFTER_S });
        if (isDeadToken(r)) await env.DB.prepare("DELETE FROM activities WHERE push_token = ?").bind(t.push_token).run();
      }
      await remember();
      return "updated";
    }
    for (const t of tokens) await send(t.push_token, { event: "end", "dismissal-date": nowS + DISMISS_AFTER_S });
    await env.DB.batch([
      env.DB.prepare("DELETE FROM activities WHERE relay_token = ?").bind(device.relay_token),
      env.DB.prepare("DELETE FROM prints WHERE relay_token = ? AND phase NOT IN ('printing','paused','preparing','error')").bind(
        device.relay_token,
      ),
      env.DB.prepare("UPDATE devices SET last_state = NULL WHERE relay_token = ?").bind(device.relay_token),
    ]);
    return "ended";
  }

  if (anyActive && device.start_token) {
    const lead = state.prints.find((p) => isActive(p.phase));
    const who = opts.starter ?? lead?.printer ?? "A printer";
    const r = await send(device.start_token, {
      event: "start",
      "attributes-type": ACTIVITY_TYPE,
      attributes: { title: "Prints" },
      "stale-date": nowS + STALE_AFTER_S,
      alert: { title: `${who} is printing`, body: lead?.jobName || "Print started" },
    });
    if (isDeadToken(r)) {
      await env.DB.prepare("UPDATE devices SET start_token = NULL WHERE relay_token = ?").bind(device.relay_token).run();
      return "none";
    }
    if (r.ok) await remember();
    return r.ok ? "started" : `none(${r.status} ${r.reason})`;
  }
  return "none";
}
