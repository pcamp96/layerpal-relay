-- One push-to-start per printing session (2026-11-11). Without this, a card whose
-- update token never reached the relay got a fresh push-to-start every cron minute.
ALTER TABLE devices ADD COLUMN start_sent_at INTEGER; -- epoch seconds of the last push-to-start; NULL once nothing is active
