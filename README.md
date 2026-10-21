# INRUUUM temporary media relay

Dedicated deployment branch. Original files remain in the platform private storage. Only expiring transfer copies are stored here. A free Render instance can lose its cache on restart or idle spin-down. No model request is automatically retried after a lost result.

Runtime: Python standard library. Required secret: ISKRA_MEDIA_RELAY_TOKEN. Render supplies PORT and RENDER_EXTERNAL_URL.

PUT /objects/{uuid} requires the platform token. GET/HEAD requires a signed URL valid for one hour. Range downloads and immutable, idempotent uploads are supported. GET /health is read only. Credentials and signed URLs are omitted from application logs.

Tests: python -m unittest discover -s relay -p 'test_*.py' -v
