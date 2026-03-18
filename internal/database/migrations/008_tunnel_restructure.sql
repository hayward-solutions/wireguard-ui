-- Restructure tunnels table: replace generic config JSON blob with structured WireGuard fields.
-- Also drop the tunnel_peers junction table (tunnels now run on separate interfaces).

-- Create new tunnels table with structured columns
CREATE TABLE IF NOT EXISTS tunnels_new (
    id                   TEXT PRIMARY KEY,
    name                 TEXT NOT NULL,
    description          TEXT DEFAULT '',
    private_key          TEXT NOT NULL,
    public_key           TEXT NOT NULL,
    address              TEXT NOT NULL DEFAULT '10.100.0.1/30',
    listen_port          INTEGER NOT NULL DEFAULT 0,
    dns                  TEXT DEFAULT '',
    mtu                  INTEGER DEFAULT 1420,
    peer_public_key      TEXT NOT NULL DEFAULT '',
    peer_endpoint        TEXT DEFAULT '',
    preshared_key        TEXT DEFAULT '',
    peer_allowed_ips     TEXT NOT NULL DEFAULT '',
    persistent_keepalive INTEGER DEFAULT 25,
    enabled              INTEGER NOT NULL DEFAULT 1,
    created_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Migrate existing tunnel data (preserving id, name, description, enabled, timestamps)
INSERT OR IGNORE INTO tunnels_new (id, name, description, private_key, public_key, enabled, created_at, updated_at)
SELECT id, name, description, '', '', enabled, created_at, updated_at
FROM tunnels;

DROP TABLE IF EXISTS tunnels;
ALTER TABLE tunnels_new RENAME TO tunnels;

DROP TABLE IF EXISTS tunnel_peers;
