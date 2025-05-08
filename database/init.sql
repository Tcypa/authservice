CREATE TABLE refreshTokens (
    id SERIAL PRIMARY KEY,
    uguid UUID NOT NULL UNIQUE,
    tokenHash TEXT NOT NULL,
    userAgent TEXT NOT NULL,
    ipAddress TEXT NOT NULL,
    issued TIMESTAMP NOT NULL,
    expires TIMESTAMP NOT NULL
);