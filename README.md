# INRUUUM temporary media relay

Dedicated deployment branch. The main branch and its static media deployments are independent.

Runtime: Python standard library. Required secret: ISKRA_MEDIA_RELAY_TOKEN. Render supplies PORT and RENDER_EXTERNAL_URL. Original files remain in the platform's private storage. This service stores only expiring transfer copies; a restart can remove them.

PUT /objects/{uuid} requires the service token. GET/HEAD requires an expiring HMAC signature. Range downloads and immutable, idempotent uploads are supported. GET /health is read only. Credentials and signed URLs are omitted from logs.
