import os
from upstash_redis import Redis

# Try loading env in case it is imported standalone
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

UPSTASH_REDIS_REST_URL = os.environ.get("UPSTASH_REDIS_REST_URL")
UPSTASH_REDIS_REST_TOKEN = os.environ.get("UPSTASH_REDIS_REST_TOKEN")

redis_client = None

if UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN:
    try:
        # Initialize Upstash Redis client
        redis_client = Redis(url=UPSTASH_REDIS_REST_URL, token=UPSTASH_REDIS_REST_TOKEN)
        # Verify connection
        redis_client.ping()
        print("[TeraBridge] Successfully connected to Upstash Redis!", flush=True)
    except Exception as e:
        print(f"[TeraBridge][ERROR] Failed to initialize Upstash Redis: {e}", flush=True)
        redis_client = None
else:
    print("[TeraBridge] Upstash Redis credentials not detected. Caching and Rate Limiting will fall back to local in-memory.", flush=True)
