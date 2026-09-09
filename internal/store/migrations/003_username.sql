-- People sign in with a username, not an email address. An email is a fact
-- about someone; a username is what they are called here, and the two do not
-- have to be the same.
--
-- Written to be re-runnable: every migration in this directory is applied on
-- every start, so a rename has to check whether it already happened.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'email'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'username'
    ) THEN
        ALTER TABLE users RENAME COLUMN email TO username;

        -- Existing rows keep working: the local part of an address is a
        -- reasonable username, and the full value stands where it is not unique.
        UPDATE users
        SET username = split_part(username, '@', 1)
        WHERE username LIKE '%@%'
          AND split_part(username, '@', 1) NOT IN (
              SELECT split_part(username, '@', 1) FROM users GROUP BY 1 HAVING count(*) > 1
          );
    END IF;
END $$;

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_username_not_blank;
ALTER TABLE users ADD CONSTRAINT users_username_not_blank CHECK (btrim(username) <> '');

-- Names differing only by case would be indistinguishable to whoever reads them.
DROP INDEX IF EXISTS users_username_lower_idx;
CREATE UNIQUE INDEX users_username_lower_idx ON users (lower(username));
