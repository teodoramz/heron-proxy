-- Two roles, not three. The distinction between viewer and analyst was that a
-- viewer could not see request bodies or act on what they found, which in
-- practice meant they could see that something happened but not what.
UPDATE users SET role = 'analyst' WHERE role = 'viewer';

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('admin', 'analyst'));
