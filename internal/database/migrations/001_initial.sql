CREATE TABLE IF NOT EXISTS server_config (
    id          TEXT PRIMARY KEY DEFAULT 'default',
    private_key TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    listen_port INTEGER NOT NULL DEFAULT 51820,
    address     TEXT NOT NULL DEFAULT '10.0.0.1/24',
    dns         TEXT DEFAULT '1.1.1.1',
    mtu         INTEGER DEFAULT 1420,
    post_up     TEXT DEFAULT '',
    post_down   TEXT DEFAULT '',
    endpoint    TEXT NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    email       TEXT NOT NULL,
    name        TEXT DEFAULT '',
    role        TEXT NOT NULL DEFAULT 'viewer',
    last_login  TIMESTAMP,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS peers (
    id                   TEXT PRIMARY KEY,
    name                 TEXT NOT NULL,
    email                TEXT DEFAULT '',
    private_key          TEXT NOT NULL,
    public_key           TEXT NOT NULL,
    preshared_key        TEXT DEFAULT '',
    allowed_ips          TEXT NOT NULL DEFAULT '0.0.0.0/0',
    address              TEXT NOT NULL,
    dns                  TEXT DEFAULT '',
    persistent_keepalive INTEGER DEFAULT 25,
    enabled              INTEGER NOT NULL DEFAULT 1,
    created_by           TEXT REFERENCES users(id),
    created_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tunnels (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    type        TEXT NOT NULL CHECK (type IN ('site-to-site', 'point-to-site')),
    description TEXT DEFAULT '',
    config      TEXT NOT NULL DEFAULT '{}',
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tunnel_peers (
    tunnel_id   TEXT NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
    peer_id     TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    PRIMARY KEY (tunnel_id, peer_id)
);
