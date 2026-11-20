-- Drops the troubleshooter's tables with their grants and policies. The history they held is lost.
DROP TABLE IF EXISTS troubleshooting_daily_counters;
DROP TABLE IF EXISTS troubleshooting_issues;
DROP TABLE IF EXISTS troubleshooting_probe_state;
DROP TABLE IF EXISTS troubleshooting_runs;
