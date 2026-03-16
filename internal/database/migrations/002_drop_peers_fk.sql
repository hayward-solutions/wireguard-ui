-- Drop FOREIGN KEY constraint on peers.created_by (SQLite requires table rebuild)
CREATE TABLE IF NOT EXISTS peers_new (
    id                   TEXT PRIMARY KEY,
    name                 TEXT NOT NULL,
    private_key          TEXT NOT NULL,
    public_key           TEXT NOT NULL,
    preshared_key        TEXT DEFAULT '',
    allowed_ips          TEXT NOT NULL DEFAULT '0.0.0.0/0',
    address              TEXT NOT NULL,
    dns                  TEXT DEFAULT '',
    persistent_keepalive INTEGER DEFAULT 25,
    enabled              INTEGER NOT NULL DEFAULT 1,
    created_by           TEXT DEFAULT '',
    created_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO peers_new SELECT * FROM peers;
DROP TABLE peers;
ALTER TABLE peers_new RENAME TO peers;
