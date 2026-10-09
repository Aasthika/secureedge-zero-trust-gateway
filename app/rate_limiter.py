from app.redis_client import redis_client

RATE_LIMIT_SCRIPT = """
local current = redis.call("INCR", KEYS[1])
local ttl = redis.call("TTL", KEYS[1])

if current == 1 or ttl < 0 then
    redis.call("EXPIRE", KEYS[1], ARGV[1])
    ttl = redis.call("TTL", KEYS[1])
end

return {current, ttl}
"""


class RateLimiter:
    def __init__(self, limit: int, window_seconds: int):
        if limit < 1:
            raise ValueError("limit must be at least 1")
        if window_seconds < 1:
            raise ValueError("window_seconds must be at least 1")

        self.limit = limit
        self.window_seconds = window_seconds

    def check(self, key: str) -> tuple[bool, int, int]:
        result = redis_client.eval(
            RATE_LIMIT_SCRIPT,
            1,
            key,
            self.window_seconds,
        )

        count = int(result[0])
        ttl = int(result[1])

        return count <= self.limit, count, max(ttl, 0)
