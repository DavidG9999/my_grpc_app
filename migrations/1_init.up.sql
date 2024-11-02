CREATE TABLE
    IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash BLOB NOT NULL,
        is_admin BOOLEAN NOT NULL DEFAULT FALSE
    );

CREATE INDEX IF NOT EXISTS idx_email ON users (email);

CREATE TABLE
    IF NOT EXISTS apps (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        secret TEXT NOT NULL UNIQUE
    );