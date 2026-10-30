CENTRAL API INTEGRATION PATCH
=============================

Contains complete updated files for the existing project:
- backend/api_server.py (adds central event endpoints)
- backend/api_client.py (new HTTP client)
- sender/app.py (central API auth + receiver discovery)
- receiver/app.py (central API auth + public-key publishing)
- admin/app.py (central API auth + account approval + central events)

Apply from the project root. Back up existing files first.
Do not overwrite backend/auth_manager.py, cryptographic keys, SQLite databases,
trusted key stores, blockchain artifacts, or IPFS data.

API host:
  export CAPSTONE_API_URL=http://127.0.0.1:8000

Other LAN devices:
  export CAPSTONE_API_URL=http://10.255.123.95:8000

The API server must be running on the central host. Keep the same
CAPSTONE_API_SECRET value for the lifetime of the API process/session.
Use HTTPS and a managed secret before using outside a trusted LAN.
