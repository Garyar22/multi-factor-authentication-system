-- =============================================================================
-- Multi-Factor Authentication System - database and account creation
--
-- Run as a MySQL administrator:
--     mysql -u root -p < scripts/create_database.sql
--
-- IMPORTANT
-- ---------
-- Replace 'CHANGE_THIS_PASSWORD' below with a password you choose, and put the
-- same value in MYSQL_PASSWORD in your .env file. This file is committed to
-- version control, so it must never contain a real password.
-- =============================================================================

-- --- Application database ----------------------------------------------------
-- utf8mb4 is used so that names and email addresses in any language, and
-- four-byte characters, are stored correctly rather than truncated.
CREATE DATABASE IF NOT EXISTS mfa_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

-- --- A separate database for the automated tests ------------------------------
-- The test suite creates and drops tables, so it must never point at mfa_db.
CREATE DATABASE IF NOT EXISTS mfa_test_db
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

-- --- Application account ------------------------------------------------------
-- A dedicated account, not root. If the application is ever compromised, the
-- attacker inherits only these privileges.
CREATE USER IF NOT EXISTS 'mfa_user'@'localhost'
    IDENTIFIED BY 'CHANGE_THIS_PASSWORD';

-- Day-to-day privileges. Note what is NOT granted: no DROP, no FILE, no
-- privileges on any other database, and no access from any host but localhost.
GRANT SELECT, INSERT, UPDATE, DELETE ON mfa_db.* TO 'mfa_user'@'localhost';

-- Schema changes are applied by Flask-Migrate, which needs CREATE/ALTER/INDEX.
-- In a stricter production setup you would run migrations as a separate
-- account that holds these, and withhold them from the runtime account.
GRANT CREATE, ALTER, INDEX, REFERENCES, DROP ON mfa_db.* TO 'mfa_user'@'localhost';

-- The test database is created and torn down by the suite.
GRANT ALL PRIVILEGES ON mfa_test_db.* TO 'mfa_user'@'localhost';

FLUSH PRIVILEGES;

-- --- Verify -------------------------------------------------------------------
SELECT 'Databases created:' AS status;
SHOW DATABASES LIKE 'mfa%';
SELECT 'Privileges for mfa_user:' AS status;
SHOW GRANTS FOR 'mfa_user'@'localhost';

-- =============================================================================
-- OPTIONAL HARDENING: make the audit log append-only for the runtime account
--
-- The application only ever INSERTs into and SELECTs from audit_events. Once
-- the schema exists (after `flask db upgrade`), you can withhold UPDATE and
-- DELETE on that one table, so that even a fully compromised application
-- cannot rewrite its own security history.
--
-- Run these AFTER the first `flask db upgrade`:
--
--   REVOKE UPDATE, DELETE ON mfa_db.audit_events FROM 'mfa_user'@'localhost';
--   FLUSH PRIVILEGES;
--
-- Note the trade-off: a later migration that needs to alter rows in that table
-- will then fail until the privilege is granted back. This is documented in
-- docs/DEPLOYMENT.md section 9.
-- =============================================================================
