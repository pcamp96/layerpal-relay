import { describe, expect, it } from "vitest";
import { p8ToDer, providerToken } from "../src/apns";
import { open, seal } from "../src/crypto";
import { type PrintRow, RECENT_DONE_S, activityState, alertPayload, parseMinutes, printUpdate, rowsFromStatuses, stateKey, wantsAlert } from "../src/events";

async function makeP8(): Promise<{ pem: string; pub: CryptoKey }> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const der = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
  const b64 = btoa(String.fromCharCode(...der));
  const pem = `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`;
  return { pem, pub: pair.publicKey };
}

function b64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

describe("APNs provider token", () => {
  it("is a valid ES256 JWT with kid/iss/iat, even from a mashed one-line .p8", async () => {
    const { pem, pub } = await makeP8();
    const mashed = pem.replace(/\n/g, " ");
    expect(p8ToDer(mashed)).toEqual(p8ToDer(pem));

    const jwt = await providerToken({ teamId: "TEAM123456", keyId: "KEYAAAAAA1", p8: mashed }, 1_000_000_000);
    const [h, c, sig] = jwt.split(".");
    expect(JSON.parse(new TextDecoder().decode(b64urlDecode(h)))).toEqual({ alg: "ES256", kid: "KEYAAAAAA1" });
    expect(JSON.parse(new TextDecoder().decode(b64urlDecode(c)))).toEqual({ iss: "TEAM123456", iat: 1_000_000 });
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      pub,
      b64urlDecode(sig),
      new TextEncoder().encode(`${h}.${c}`),
    );
    expect(ok).toBe(true);
    expect(await providerToken({ teamId: "TEAM123456", keyId: "KEYAAAAAA1", p8: pem }, 1_000_000_000 + 600_000)).toBe(jwt);
  });
});

describe("Bambuddy webhook mapping", () => {
  const now = 1_800_000_000;

  it("parses Bambuddy durations", () => {
    expect(parseMinutes("2h 5m")).toBe(125);
    expect(parseMinutes("45m")).toBe(45);
    expect(parseMinutes("Unknown")).toBe(0);
  });

  it("turns start/progress/end events into print state", () => {
    expect(printUpdate({ event: "print_start", printer: "X2D", filename: "Benchy", estimated_time: "1h 30m" }, now)).toMatchObject({
      printer: "X2D",
      phase: "printing",
      progress: 0,
      finish_at: now + 90 * 60,
      job: "Benchy",
    });
    expect(printUpdate({ event: "print_progress", printer: "X2D", progress: "50", remaining_time: "45m" }, now)).toMatchObject({
      progress: 50,
      finish_at: now + 45 * 60,
    });
    expect(printUpdate({ event: "print_complete", printer: "X2D" }, now)).toMatchObject({ phase: "finished", progress: 100 });
    expect(printUpdate({ event: "printer_offline", printer: "X2D" }, now)).toBeNull();
  });

  it("only notifies (vs. updating the card) for events that need attention", () => {
    expect(wantsAlert("print_start")).toBe(false);
    expect(wantsAlert("print_progress")).toBe(false);
    expect(wantsAlert("print_complete")).toBe(true);
  });

  it("builds a card: problems first, then soonest finish, with counts and an animatable start", () => {
    const rows: PrintRow[] = [
      { printer: "P2S", phase: "printing", progress: 20, finish_at: now + 3600, job: "Vase", updated_at: now, layer: 40, total_layers: 200 },
      { printer: "H3C", phase: "finished", progress: 100, finish_at: 0, job: "Gear", updated_at: now - 60 },
      { printer: "X2D", phase: "printing", progress: 80, finish_at: now + 600, job: "Benchy", updated_at: now },
      { printer: "A1", phase: "paused", progress: 10, finish_at: now + 900, job: "Clip", updated_at: now },
      { printer: "Old", phase: "finished", progress: 100, finish_at: 0, job: "Old", updated_at: now - RECENT_DONE_S - 1 },
    ];
    const s = activityState(rows, now);
    expect(s.prints.map((p) => p.printer)).toEqual(["A1", "X2D", "P2S", "H3C"]);
    expect([s.printing, s.paused, s.errors]).toEqual([2, 1, 0]);
    const p2s = s.prints.find((p) => p.printer === "P2S")!;
    expect(p2s).toMatchObject({ layer: 40, totalLayers: 200, finishAt: now + 3600 });
    // 20% done with 60 min left => 75 min total => started 15 min ago
    expect(p2s.startAt).toBe(now - 15 * 60);
    expect(s.prints.find((p) => p.printer === "A1")!.startAt).toBe(0); // paused bars don't animate
  });

  it("maps a bulk status snapshot to card rows (ignoring idle printers and the auth-lock HMS)", () => {
    const printers = [
      { id: 1, name: "X2D" },
      { id: 2, name: "P2S" },
      { id: 3, name: "H3C" },
      { id: 4, name: "Spare", is_active: false },
    ];
    const statuses = [
      { id: 1, connected: true, state: "RUNNING", progress: 42.6, remaining_time: 30, layer_num: 12, total_layers: 90, subtask_name: "Big_Benchy",
        hms_errors: [{ severity: 1, full_code: "0500050000010007" }] },
      { id: 2, connected: true, state: "IDLE" },
      { id: 3, connected: true, state: "FINISH", subtask_name: "Gear" },
    ];
    const existing = new Map<string, PrintRow>([
      ["H3C", { printer: "H3C", phase: "printing", progress: 90, finish_at: now + 60, job: "Gear", updated_at: now - 60 }],
    ]);
    const rows = rowsFromStatuses(printers, statuses, existing, now);
    expect(rows).toEqual([
      { printer: "X2D", phase: "printing", progress: 43, finish_at: now + 1800, job: "Big Benchy", updated_at: now, layer: 12, total_layers: 90 },
      { printer: "H3C", phase: "finished", progress: 100, finish_at: 0, job: "Gear", updated_at: now, layer: 0, total_layers: 0 },
    ]);
    const faulted = rowsFromStatuses(printers, [{ ...statuses[0], hms_errors: [{ severity: 1, full_code: "0300120000010001" }] }], new Map(), now);
    expect(faulted[0].phase).toBe("error");
  });

  it("change key ignores the clock but not progress", () => {
    const rows: PrintRow[] = [{ printer: "X2D", phase: "printing", progress: 50, finish_at: now + 600, job: "B", updated_at: now }];
    const a = stateKey(activityState(rows, now));
    expect(stateKey(activityState(rows, now + 30))).toBe(a);
    expect(stateKey(activityState([{ ...rows[0], progress: 51 }], now))).not.toBe(a);
  });

  it("keeps the Live Activity payload well under APNs' 4 KB limit with a full farm", () => {
    const rows: PrintRow[] = Array.from({ length: 80 }, (_, i) => ({
      printer: `Farm printer number ${i}`,
      phase: i % 9 === 0 ? "paused" : "printing",
      progress: i,
      finish_at: now + i * 600,
      job: "A fairly long project name for a multi-plate print job",
      updated_at: now,
      layer: 100,
      total_layers: 400,
    }));
    const s = activityState(rows, now);
    expect(s.printing + s.paused).toBe(80);
    expect(JSON.stringify({ aps: { timestamp: now, event: "update", "content-state": s } }).length).toBeLessThan(2000);
  });

  it("seals and opens poll keys", async () => {
    const secret = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
    const sealed = await seal(secret, "bb_example_key");
    expect(sealed).not.toContain("bb_example");
    expect(await open(secret, sealed)).toBe("bb_example_key");
  });

  it("builds alert payloads the app understands, with the MakerWorld nudge", () => {
    const p = alertPayload({
      event: "print_complete",
      title: "Print complete",
      message: "Benchy finished",
      printer: "X2D",
      finish_photo_url: "https://b/photo.jpg",
      makerworld_url: "https://makerworld.com/en/models/1",
      image: "aGVsbG8=",
    }) as { aps: Record<string, unknown>; bambuddy: Record<string, unknown> };
    expect(p.aps.category).toBe("MAKERWORLD_MAKE");
    expect(p.aps["mutable-content"]).toBe(1);
    expect(p.bambuddy).toEqual({
      event_type: "print_complete",
      printer_name: "X2D",
      image_url: "https://b/photo.jpg",
      makerworld_url: "https://makerworld.com/en/models/1",
    });
    expect(JSON.stringify(p).length).toBeLessThan(4096);
  });
});
