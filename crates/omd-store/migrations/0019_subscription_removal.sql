-- Keep observations and notification history while removing an active subscription.
ALTER TABLE subscriptions ADD COLUMN removed INTEGER NOT NULL DEFAULT 0;
