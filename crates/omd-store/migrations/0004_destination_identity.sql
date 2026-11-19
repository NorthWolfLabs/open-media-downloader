ALTER TABLE destinations ADD COLUMN marker TEXT;
-- An older v2 destination without a marker stays unavailable until the user
-- explicitly reconnects it. Never adopt whatever happens to occupy its path.
