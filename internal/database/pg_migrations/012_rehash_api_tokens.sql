-- Migration 012: Clear API tokens for HMAC rehash
--
-- API token storage has been upgraded from unsalted SHA-256 to keyed HMAC-SHA256.
-- Existing token hashes are incompatible with the new scheme and must be cleared.
-- Users will need to re-create their API tokens after this upgrade.
DELETE FROM api_tokens;
