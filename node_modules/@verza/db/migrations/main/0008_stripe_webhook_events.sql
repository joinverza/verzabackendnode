CREATE TABLE IF NOT EXISTS stripe_webhook_events (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    stripe_payment_intent_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_stripe_webhook_events_pi ON stripe_webhook_events(stripe_payment_intent_id);
