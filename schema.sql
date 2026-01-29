CREATE TABLE IF NOT EXISTS events (
  event_time DateTime,
  source String,
  event_type String,
  payload String
) ENGINE = MergeTree()
ORDER BY event_time;