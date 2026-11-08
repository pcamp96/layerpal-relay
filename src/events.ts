// Live Activity model + Bambuddy webhook / status mapping.

export interface BambuddyWebhook {
  title?: string;
  message?: string;
  event?: string;
  printer?: string;
  filename?: string;
  progress?: string | number;
  remaining_time?: string;
  estimated_time?: string;
  snapshot_url?: string;
  finish_photo_url?: string;
  makerworld_url?: string;
  [key: string]: unknown;
}

/** One row on the card. Must match PrintItem in the app. */
export interface PrintItem {
  printer: string;
  /** printing | paused | error | finished | failed | stopped */
  phase: string;
  progress: number;
  layer: number;
  totalLayers: number;
  /** Epoch seconds. With finishAt, lets iOS animate the bar between pushes. 0 = unknown. */
  startAt: number;
  finishAt: number;
  jobName: string;
}

/** Must match PrintsActivityAttributes.ContentState in the app. */
export interface ActivityState {
  prints: PrintItem[];
  printing: number;
  paused: number;
  errors: number;
  updatedAt: number;
}

export const ACTIVITY_TYPE = "PrintsActivityAttributes";
const ACTIVE = new Set(["preparing", "printing", "paused", "error"]);
/** Finished prints stay on the card this long so you see "done". */
export const RECENT_DONE_S = 15 * 60;
const MAX_ROWS = 4;
/** HMS 0500-0500-0001-0007: cloud-mode authorization lock, not a real fault. */
const AUTH_LOCK = "0500050000010007";

export const isActive = (phase: string) => ACTIVE.has(phase);

export interface PrintRow {
  printer: string;
  phase: string;
  progress: number;
  finish_at: number;
  job: string;
  updated_at: number;
  layer?: number;
  total_layers?: number;
}

/** Bambuddy formats durations as "2h 5m" or "45m" ("Unknown" when missing). */
export function parseMinutes(text: unknown): number {
  if (typeof text !== "string") return 0;
  const h = /(\d+)\s*h/.exec(text);
  const m = /(\d+)\s*m/.exec(text);
  return (h ? parseInt(h[1], 10) * 60 : 0) + (m ? parseInt(m[1], 10) : 0);
}

function clampProgress(p: unknown): number {
  const n = typeof p === "number" ? p : parseInt(String(p ?? "0"), 10);
  return Number.isFinite(n) ? Math.max(0, Math.min(100, Math.round(n))) : 0;
}

/** The print-state change a webhook implies, or null for non-print events. */
export function printUpdate(w: BambuddyWebhook, nowS: number): PrintRow | null {
  const printer = typeof w.printer === "string" && w.printer ? w.printer : null;
  if (!printer) return null;
  const job = typeof w.filename === "string" ? w.filename : "";
  const finishIn = (text: unknown) => {
    const m = parseMinutes(text);
    return m > 0 ? nowS + m * 60 : 0;
  };
  const row = (phase: string, progress: number, finish_at: number): PrintRow => ({
    printer,
    phase,
    progress,
    finish_at,
    job,
    updated_at: nowS,
  });
  switch (w.event) {
    case "print_start":
      return row("printing", 0, finishIn(w.estimated_time));
    case "print_progress":
      return row("printing", clampProgress(w.progress), finishIn(w.remaining_time));
    case "print_complete":
      return row("finished", 100, 0);
    case "print_failed":
      return row("failed", clampProgress(w.progress), 0);
    case "print_stopped":
      return row("stopped", clampProgress(w.progress), 0);
    default:
      return null;
  }
}

/** Start/progress feed the card quietly; everything else is a notification. */
export function wantsAlert(event: string | undefined): boolean {
  return event !== "print_start" && event !== "print_progress";
}

// MARK: Polling (GET /bulk/printer-statuses)

export interface PrinterLite {
  id: number;
  name: string;
  is_active?: boolean;
}

export interface StatusLite {
  id: number;
  connected?: boolean;
  state?: string | null;
  progress?: number | null;
  remaining_time?: number | null; // minutes
  layer_num?: number | null;
  total_layers?: number | null;
  subtask_name?: string | null;
  gcode_file?: string | null;
  hms_errors?: { severity?: number; full_code?: string }[] | null;
}

function jobName(s: StatusLite): string {
  const raw = s.subtask_name || s.gcode_file || "";
  return raw.replace(/_/g, " ").replace(/\.gcode(\.3mf)?$/, "");
}

function hasFault(s: StatusLite): boolean {
  return (s.hms_errors ?? []).some((e) => (e.severity ?? 1) === 1 && (e.full_code ?? "").toUpperCase() !== AUTH_LOCK);
}

/**
 * Rows to upsert from a status snapshot. Active printers always get a row;
 * printers that just stopped get their final phase only if they were on the
 * card (so idle printers don't flood it).
 */
export function rowsFromStatuses(
  printers: PrinterLite[],
  statuses: StatusLite[],
  existing: Map<string, PrintRow>,
  nowS: number,
): PrintRow[] {
  const byId = new Map(statuses.map((s) => [s.id, s]));
  const out: PrintRow[] = [];
  for (const p of printers) {
    if (p.is_active === false) continue;
    const s = byId.get(p.id);
    if (!s || !s.connected) continue;
    const state = (s.state ?? "").toUpperCase();
    const prev = existing.get(p.name);
    let phase: string | null = null;
    if (state === "RUNNING" || state === "PREPARE" || state === "SLICING") phase = hasFault(s) ? "error" : "printing";
    else if (state === "PAUSE") phase = hasFault(s) ? "error" : "paused";
    else if (prev && isActive(prev.phase)) phase = state === "FINISH" ? "finished" : state === "FAILED" ? "failed" : "stopped";
    if (!phase) continue;
    const remaining = s.remaining_time ?? 0;
    out.push({
      printer: p.name,
      phase,
      progress: phase === "finished" ? 100 : Math.max(0, Math.min(100, Math.round(s.progress ?? 0))),
      finish_at: isActive(phase) && remaining > 0 ? nowS + remaining * 60 : 0,
      job: jobName(s) || prev?.job || "",
      updated_at: nowS,
      layer: s.layer_num ?? 0,
      total_layers: s.total_layers ?? 0,
    });
  }
  return out;
}

// MARK: Card

/** Start time implied by progress + remaining, so iOS can animate the bar. */
export function impliedStart(r: PrintRow): number {
  if (!r.finish_at || r.finish_at <= r.updated_at) return 0;
  const p = r.progress / 100;
  if (p <= 0) return r.updated_at;
  if (p >= 0.995) return 0;
  const total = (r.finish_at - r.updated_at) / (1 - p);
  return Math.round(r.finish_at - total);
}

const RANK: Record<string, number> = { error: 0, paused: 1, printing: 2, preparing: 2 };

/** Problems first, then soonest-finishing prints, then recently finished. */
export function activityState(rows: PrintRow[], nowS: number): ActivityState {
  const keep = rows.filter((r) => isActive(r.phase) || nowS - r.updated_at <= RECENT_DONE_S);
  keep.sort((a, b) => {
    const ra = RANK[a.phase] ?? 3;
    const rb = RANK[b.phase] ?? 3;
    if (ra !== rb) return ra - rb;
    const af = a.finish_at || Number.MAX_SAFE_INTEGER;
    const bf = b.finish_at || Number.MAX_SAFE_INTEGER;
    return af - bf || a.printer.localeCompare(b.printer);
  });
  return {
    prints: keep.slice(0, MAX_ROWS).map((r) => ({
      printer: r.printer,
      phase: r.phase,
      progress: r.progress,
      layer: r.layer ?? 0,
      totalLayers: r.total_layers ?? 0,
      startAt: isActive(r.phase) && r.phase !== "paused" ? impliedStart(r) : 0,
      finishAt: r.finish_at,
      jobName: r.job,
    })),
    printing: keep.filter((r) => r.phase === "printing" || r.phase === "preparing").length,
    paused: keep.filter((r) => r.phase === "paused").length,
    errors: keep.filter((r) => r.phase === "error").length,
    updatedAt: nowS,
  };
}

/** Change detector that ignores the clock (and tiny ETA jitter). */
export function stateKey(s: ActivityState): string {
  return JSON.stringify(
    s.prints.map((p) => [p.printer, p.phase, p.progress, p.layer, Math.round(p.finishAt / 120)]).concat([[s.printing, s.paused, s.errors]]),
  );
}

/** Same shape the app handles: aps + "bambuddy" custom dictionary. */
export function alertPayload(w: BambuddyWebhook): Record<string, unknown> {
  const event = w.event ?? "unknown";
  const printer = typeof w.printer === "string" ? w.printer : undefined;
  const makerworld = event === "print_complete" && typeof w.makerworld_url === "string" ? w.makerworld_url : undefined;
  let body = typeof w.message === "string" ? w.message : "";
  let category = printer ? "PRINTER_EVENT" : "GENERAL";
  if (makerworld) {
    category = "MAKERWORLD_MAKE";
    body = `${body}\nGot a good shot? Upload a photo of your make to MakerWorld.`;
  }
  const image = [w.finish_photo_url, w.snapshot_url].find((u) => typeof u === "string" && u.length > 0) as
    | string
    | undefined;

  const aps: Record<string, unknown> = {
    alert: { title: typeof w.title === "string" ? w.title : "LayerPal", body },
    sound: "default",
    category,
  };
  if (image) aps["mutable-content"] = 1;
  if (printer) aps["thread-id"] = `printer-${printer}`;

  const custom: Record<string, unknown> = { event_type: event };
  if (printer) custom.printer_name = printer;
  if (image) custom.image_url = image;
  if (makerworld) custom.makerworld_url = makerworld;
  return { aps, bambuddy: custom };
}
