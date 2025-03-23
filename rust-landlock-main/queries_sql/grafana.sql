-- ============================================
-- Supernanny SOC Dashboard - Grafana SQL Panels
-- Compatible with PostgreSQL and Grafana macros
-- ============================================

-- 1️⃣ Denied Events Over Time
-- Type: Time Series
SELECT
  date_trunc('minute', timestamp) AS "time",
  COUNT(*) AS "Denied Events"
FROM sandbox_events
WHERE result = 'denied' AND $__timeFilter(timestamp)
GROUP BY "time"
ORDER BY "time";


-- 2️⃣ Events by User
-- Type: Bar Chart / Table
SELECT
  u.username,
  COUNT(*) AS "Events"
FROM sandbox_events se
JOIN users u ON se.user_id = u.user_id
WHERE $__timeFilter(se.timestamp)
GROUP BY u.username
ORDER BY "Events" DESC
LIMIT 10;


-- 3️⃣ Most Violated Applications
-- Type: Bar Chart
SELECT
  app_name,
  COUNT(*) AS "Denied Count"
FROM sandbox_events
WHERE result = 'denied' AND $__timeFilter(timestamp)
GROUP BY app_name
ORDER BY "Denied Count" DESC
LIMIT 10;


-- 4️⃣ Top Denied Operations
-- Type: Pie Chart / Bar Chart
SELECT
  operation,
  COUNT(*) AS "Count"
FROM sandbox_events
WHERE result = 'denied' AND $__timeFilter(timestamp)
GROUP BY operation
ORDER BY "Count" DESC
LIMIT 10;


-- 5️⃣ Denied Paths by Application
-- Type: Table
SELECT
  app_name,
  denied_path,
  COUNT(*) AS "Denial Count"
FROM sandbox_events
WHERE result = 'denied' AND denied_path IS NOT NULL AND $__timeFilter(timestamp)
GROUP BY app_name, denied_path
ORDER BY "Denial Count" DESC
LIMIT 10;


-- 6️⃣ Events by Host
-- Type: Bar / Table
SELECT
  hostname,
  COUNT(*) AS "Events"
FROM sandbox_events
WHERE $__timeFilter(timestamp)
GROUP BY hostname
ORDER BY "Events" DESC
LIMIT 10;


-- 7️⃣ Total Sandbox Events
-- Type: Stat Panel
SELECT COUNT(*) AS "Total Events"
FROM sandbox_events
WHERE $__timeFilter(timestamp);


-- 8️⃣ Live Events (Last 100)
-- Type: Log Table / Table
SELECT
  timestamp,
  hostname,
  app_name,
  operation,
  result,
  denied_path,
  user_id
FROM sandbox_events
WHERE $__timeFilter(timestamp)
ORDER BY timestamp DESC
LIMIT 100;
