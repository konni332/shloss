ALTER TABLE password_credentials
ADD COLUMN vault_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000';

ALTER TABLE password_credentials ALTER COLUMN vault_id
DROP DEFAULT;

ALTER TABLE password_credentials
DROP CONSTRAINT password_credentials_username_key;

ALTER TABLE password_credentials
ADD CONSTRAINT password_credentials_username_vault_unique UNIQUE (username, vault_id);
