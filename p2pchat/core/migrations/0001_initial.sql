-- Initial schema for p2pchat local storage.
-- Applied automatically by the migration runner on first open.

-- IMPORTANT: Migration SQL files must NEVER contain semicolons inside string
-- literals, trigger bodies, or comments.  The migration runner splits on the
-- semicolon character and executes each part individually.  An embedded
-- semicolon in a string value or trigger body will produce broken SQL.
-- Use only simple DDL/DML with no embedded semicolons.

CREATE TABLE IF NOT EXISTS account (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    user_id      TEXT    NOT NULL,
    display_name TEXT    NOT NULL,
    created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS contacts (
    peer_id      TEXT    PRIMARY KEY,
    display_name TEXT    NOT NULL,
    ygg_address  TEXT,
    x25519_pub   TEXT    NOT NULL,
    trusted      INTEGER NOT NULL DEFAULT 0 CHECK (trusted IN (0, 1)),
    added_at     INTEGER NOT NULL CHECK (added_at > 0),
    last_seen    INTEGER
);

CREATE TABLE IF NOT EXISTS messages (
    id        TEXT    PRIMARY KEY,
    peer_id   TEXT    NOT NULL,
    direction TEXT    NOT NULL CHECK (direction IN ('sent', 'received')),
    content   TEXT    NOT NULL,
    timestamp INTEGER NOT NULL CHECK (timestamp > 0),
    delivered INTEGER NOT NULL DEFAULT 0 CHECK (delivered IN (0, 1)),
    deleted   INTEGER NOT NULL DEFAULT 0 CHECK (deleted   IN (0, 1)),
    FOREIGN KEY (peer_id) REFERENCES contacts(peer_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS outbox (
    id             TEXT    PRIMARY KEY,
    peer_id        TEXT    NOT NULL,
    encrypted_blob TEXT    NOT NULL,
    signature      TEXT    NOT NULL,
    created_at     INTEGER NOT NULL,
    message_id     TEXT    REFERENCES messages(id) ON DELETE SET NULL,
    attempts       INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_attempt   INTEGER,
    FOREIGN KEY (peer_id) REFERENCES contacts(peer_id) ON DELETE CASCADE
);

-- Covering index: peer + deleted filter + timestamp order matches get_messages() query
CREATE INDEX IF NOT EXISTS idx_messages_peer_del_ts ON messages(peer_id, deleted, timestamp);
CREATE INDEX IF NOT EXISTS idx_outbox_peer_id       ON outbox(peer_id);
