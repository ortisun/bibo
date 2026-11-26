-- Puts bump_guard back on attempts: every update raises the version by exactly one, a lease renewal
-- included. Code written for migration 33 renews without raising it and is refused after this.

SET LOCAL lock_timeout = '5s';

DROP TRIGGER attempts_bump ON attempts;
CREATE TRIGGER attempts_bump BEFORE UPDATE ON attempts FOR EACH ROW EXECUTE FUNCTION bump_guard();
DROP FUNCTION attempts_bump_guard();
