from prometheus_client import Counter, Histogram


http_requests_total = Counter(
    "secureedge_http_requests_total",
    "Total number of HTTP requests handled by SecureEdge",
    ["method", "status"],
)


http_request_duration_seconds = Histogram(
    "secureedge_http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "status"],
)

rate_limited_requests_total = Counter(
    "secureedge_rate_limited_requests_total",
    "Total number of requests rejected by the rate limiter",
)
