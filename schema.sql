-- LayerPal push relay. One row per installed app (phone); relay_token is the
-- secret in that phone's webhook URL.
CREATE TABLE IF NOT EXISTS devices (
  relay_token  TEXT PRIMARY KEY,
  device_token TEXT NOT NULL,
  environment  TEXT NOT NULL CHECK (environment IN ('sandbox', 'production')),
  start_token  TEXT,              -- Live Activity push-to-start token (iOS 17.2+)
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL,
  last_hook_at INTEGER
);

-- Running Live Activities, keyed by printer name (Bambuddy webhooks carry names, not ids).
CREATE TABLE IF NOT EXISTS activities (
  push_token  TEXT PRIMARY KEY,
  relay_token TEXT NOT NULL REFERENCES devices(relay_token) ON DELETE CASCADE,
  printer     TEXT NOT NULL,
  created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS activities_by_printer ON activities (relay_token, printer);

-- Latest known state of each printer's job, per phone. Feeds the single
-- "all active prints" Live Activity.
CREATE TABLE IF NOT EXISTS prints (
  relay_token TEXT NOT NULL REFERENCES devices(relay_token) ON DELETE CASCADE,
  printer     TEXT NOT NULL,
  phase       TEXT NOT NULL,       -- printing | paused | finished | failed | stopped
  progress    INTEGER NOT NULL,
  finish_at   INTEGER NOT NULL,    -- epoch seconds; 0 when unknown
  job         TEXT NOT NULL,
  updated_at  INTEGER NOT NULL,    -- epoch seconds
  PRIMARY KEY (relay_token, printer)
);
