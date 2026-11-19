CREATE TABLE browser_packages (
 digest TEXT PRIMARY KEY, label TEXT NOT NULL, review_json TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('installed','removing','retained','removed')),
 revision INTEGER NOT NULL DEFAULT 1, installed_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 issue_json TEXT
);
CREATE TABLE browser_package_active (singleton INTEGER PRIMARY KEY CHECK(singleton=1), digest TEXT REFERENCES browser_packages(digest));
INSERT INTO browser_package_active VALUES(1,NULL);
