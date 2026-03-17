CREATE TABLE IF NOT EXISTS groups (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    source     TEXT NOT NULL DEFAULT 'local' CHECK (source IN ('local', 'oidc')),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_groups (
    user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    source   TEXT NOT NULL DEFAULT 'local' CHECK (source IN ('local', 'oidc')),
    PRIMARY KEY (user_id, group_id)
);

CREATE INDEX IF NOT EXISTS idx_user_groups_user ON user_groups(user_id);
CREATE INDEX IF NOT EXISTS idx_user_groups_group ON user_groups(group_id);

CREATE TABLE IF NOT EXISTS acl_rules (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT DEFAULT '',
    priority    INTEGER NOT NULL DEFAULT 100,
    action      TEXT NOT NULL DEFAULT 'allow' CHECK (action IN ('allow')),
    protocol    TEXT NOT NULL DEFAULT 'any' CHECK (protocol IN ('any', 'tcp', 'udp')),
    dst_cidr    TEXT NOT NULL,
    dst_ports   TEXT DEFAULT '',
    group_id    TEXT REFERENCES groups(id) ON DELETE CASCADE,
    user_id     TEXT REFERENCES users(id) ON DELETE CASCADE,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (NOT (group_id IS NOT NULL AND user_id IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_acl_rules_group ON acl_rules(group_id);
CREATE INDEX IF NOT EXISTS idx_acl_rules_user ON acl_rules(user_id);
CREATE INDEX IF NOT EXISTS idx_acl_rules_priority ON acl_rules(priority);
