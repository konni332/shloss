ALTER TABLE password_credentials
ADD CONSTRAINT unique_user_id UNIQUE (user_id);
