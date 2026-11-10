-- =====================================================================
-- Account Takeover (ATO) detection rules — SQLite
-- Tables: logins(ts, customer_id, ip, country, city, lat, lon, device_id, result, mfa)
--         account_events(ts, customer_id, event_type, detail, amount_myr)
-- Each block starts with "-- name:" so analyze.py can run them one by one.
-- You can also paste any block into DB Browser for SQLite and run it.
-- =====================================================================

-- name: new_device
-- A successful login from a device this customer has never used before,
-- for customers with at least 3 days of history (so day-1 devices don't count).
WITH first_seen AS (
    SELECT customer_id, device_id, MIN(ts) AS first_ts
    FROM logins WHERE result = 'SUCCESS'
    GROUP BY customer_id, device_id
),
history AS (
    SELECT customer_id, MIN(ts) AS customer_first_ts FROM logins GROUP BY customer_id
)
SELECT f.customer_id, f.device_id, f.first_ts AS ts, l.city, l.country
FROM first_seen f
JOIN history h USING (customer_id)
JOIN logins l ON l.customer_id = f.customer_id AND l.device_id = f.device_id AND l.ts = f.first_ts
WHERE julianday(f.first_ts) - julianday(h.customer_first_ts) >= 3
ORDER BY ts;

-- name: new_country
-- First successful login from a country this customer never used before.
WITH first_country AS (
    SELECT customer_id, country, MIN(ts) AS first_ts
    FROM logins WHERE result = 'SUCCESS'
    GROUP BY customer_id, country
),
home AS (
    SELECT customer_id, MIN(ts) AS customer_first_ts FROM logins GROUP BY customer_id
)
SELECT c.customer_id, c.country, c.first_ts AS ts
FROM first_country c JOIN home h USING (customer_id)
WHERE c.first_ts > h.customer_first_ts
  AND c.country <> (SELECT country FROM logins l
                    WHERE l.customer_id = c.customer_id ORDER BY ts LIMIT 1)
ORDER BY ts;

-- name: failed_then_success
-- 3+ failed logins from the same device within 10 minutes, then a success.
SELECT s.customer_id, s.device_id, s.ts, s.city,
       COUNT(f.ts) AS fails_before
FROM logins s
JOIN logins f
  ON f.customer_id = s.customer_id AND f.device_id = s.device_id
 AND f.result = 'FAIL'
 AND f.ts < s.ts
 AND (julianday(s.ts) - julianday(f.ts)) * 24 * 60 <= 10
WHERE s.result = 'SUCCESS'
GROUP BY s.customer_id, s.device_id, s.ts
HAVING COUNT(f.ts) >= 3
ORDER BY s.ts;

-- name: sensitive_after_new_device
-- Profile changes (email, phone, password, payee, address) within 60 min
-- of a NEW-device login. Fraud teams call this "change before cash-out".
WITH first_seen AS (
    SELECT customer_id, device_id, MIN(ts) AS first_ts
    FROM logins WHERE result = 'SUCCESS' GROUP BY customer_id, device_id
),
history AS (SELECT customer_id, MIN(ts) AS customer_first_ts FROM logins GROUP BY customer_id),
new_dev AS (
    SELECT f.* FROM first_seen f JOIN history h USING (customer_id)
    WHERE julianday(f.first_ts) - julianday(h.customer_first_ts) >= 3
)
SELECT e.customer_id, n.device_id, n.first_ts AS login_ts, e.ts AS event_ts,
       e.event_type, e.detail,
       ROUND((julianday(e.ts) - julianday(n.first_ts)) * 24 * 60) AS minutes_after
FROM account_events e
JOIN new_dev n ON n.customer_id = e.customer_id
WHERE e.event_type IN ('EMAIL_CHANGE', 'PHONE_CHANGE', 'PASSWORD_RESET', 'ADD_PAYEE', 'ADD_ADDRESS')
  AND (julianday(e.ts) - julianday(n.first_ts)) * 24 * 60 BETWEEN -15 AND 60
ORDER BY e.ts;

-- name: money_after_new_device
-- Money leaving the account within 60 min of a NEW-device login.
WITH first_seen AS (
    SELECT customer_id, device_id, MIN(ts) AS first_ts
    FROM logins WHERE result = 'SUCCESS' GROUP BY customer_id, device_id
),
history AS (SELECT customer_id, MIN(ts) AS customer_first_ts FROM logins GROUP BY customer_id),
new_dev AS (
    SELECT f.* FROM first_seen f JOIN history h USING (customer_id)
    WHERE julianday(f.first_ts) - julianday(h.customer_first_ts) >= 3
)
SELECT e.customer_id, n.device_id, COUNT(*) AS transfers,
       ROUND(SUM(e.amount_myr), 2) AS total_myr, MIN(e.ts) AS first_transfer
FROM account_events e
JOIN new_dev n ON n.customer_id = e.customer_id
WHERE e.event_type = 'TRANSFER'
  AND (julianday(e.ts) - julianday(n.first_ts)) * 24 * 60 BETWEEN 0 AND 60
GROUP BY e.customer_id, n.device_id
ORDER BY total_myr DESC;

-- name: shared_payee
-- The same NEW payee added by 3+ different customers = likely a mule account.
SELECT detail AS payee,
       COUNT(DISTINCT customer_id) AS victims,
       GROUP_CONCAT(DISTINCT customer_id) AS customers,
       MIN(ts) AS first_added, MAX(ts) AS last_added
FROM account_events
WHERE event_type = 'ADD_PAYEE'
GROUP BY detail
HAVING COUNT(DISTINCT customer_id) >= 3;

-- name: sim_swap
-- Phone number changed, then a new device logs in within 60 min.
-- Classic SIM-swap pattern: attacker takes over the phone number to receive OTPs.
WITH first_seen AS (
    SELECT customer_id, device_id, MIN(ts) AS first_ts
    FROM logins WHERE result = 'SUCCESS' GROUP BY customer_id, device_id
)
SELECT p.customer_id, p.ts AS phone_change_ts, f.device_id, f.first_ts AS new_device_ts,
       ROUND((julianday(f.first_ts) - julianday(p.ts)) * 24 * 60) AS minutes_after
FROM account_events p
JOIN first_seen f ON f.customer_id = p.customer_id
WHERE p.event_type = 'PHONE_CHANGE'
  AND (julianday(f.first_ts) - julianday(p.ts)) * 24 * 60 BETWEEN 0 AND 60;
