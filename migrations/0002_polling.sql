-- Relay polling (2026-11-07): the relay checks each phone's Bambuddy once a
-- minute while a Live Activity is running, using a read-only key.
ALTER TABLE devices ADD COLUMN server_url TEXT;
ALTER TABLE devices ADD COLUMN poll_key TEXT;      -- AES-GCM ciphertext (iv:ct, base64)
ALTER TABLE devices ADD COLUMN last_state TEXT;    -- hash of the last content-state pushed
ALTER TABLE devices ADD COLUMN last_push_at INTEGER;
ALTER TABLE devices ADD COLUMN last_poll_error TEXT;
ALTER TABLE prints ADD COLUMN layer INTEGER NOT NULL DEFAULT 0;
ALTER TABLE prints ADD COLUMN total_layers INTEGER NOT NULL DEFAULT 0;
