-- APIShield schema. Idempotent: applied at startup by SecurityEventSchemaInitializer.
-- gen_random_uuid() is built in from PostgreSQL 13 (docker-compose uses postgres:18).

CREATE TABLE IF NOT EXISTS security_events (
    id                  UUID               PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id          TEXT               NOT NULL,
    occurred_at         TIMESTAMPTZ        NOT NULL,
    method              TEXT               NOT NULL,
    path                TEXT               NOT NULL,
    client_ip           TEXT               NOT NULL,
    user_id             TEXT,
    route_id            TEXT,
    decision            TEXT               NOT NULL,
    decision_reason     TEXT               NOT NULL,
    risk_score          DOUBLE PRECISION   NOT NULL CHECK (risk_score >= 0 AND risk_score <= 1),
    threat_score        DOUBLE PRECISION   NOT NULL CHECK (threat_score >= 0 AND threat_score <= 1),
    -- Threat signals as parallel arrays: element i of each array describes the same signal.
    signal_detectors    TEXT[]             NOT NULL,
    signal_detected     BOOLEAN[]          NOT NULL,
    signal_severities   DOUBLE PRECISION[] NOT NULL,
    signal_descriptions TEXT[]             NOT NULL,
    CONSTRAINT security_events_signal_arrays_aligned CHECK (
        cardinality(signal_detectors) = cardinality(signal_detected)
        AND cardinality(signal_detectors) = cardinality(signal_severities)
        AND cardinality(signal_detectors) = cardinality(signal_descriptions)
    )
);

-- Newest-first listing (the default dashboard query).
CREATE INDEX IF NOT EXISTS idx_security_events_occurred_at
    ON security_events (occurred_at DESC, id DESC);

-- Newest-first listing filtered by decision.
CREATE INDEX IF NOT EXISTS idx_security_events_decision_occurred_at
    ON security_events (decision, occurred_at DESC, id DESC);

-- Correlating an event with gateway logs. Not unique: Netty request ids restart with the process.
CREATE INDEX IF NOT EXISTS idx_security_events_request_id
    ON security_events (request_id);

-- Per-user history; partial because unauthenticated events have no user.
CREATE INDEX IF NOT EXISTS idx_security_events_user_id_occurred_at
    ON security_events (user_id, occurred_at DESC)
    WHERE user_id IS NOT NULL;
