# PisoNet Server Release

Release channel for the PisoNet Windows server.

- Branch: `release/server`
- Server build: `0.17`
- Package contents: `server.py`, coin signal and serial adapter modules, `web/admin_v2.html`, and `manifest.json`.

`manifest.json` lists SHA-256 hashes for the payload files. The live database, environment configuration, service credentials, logs, and client installers are intentionally excluded.

An OTA updater should stage and verify this payload, preserve local configuration and the SQLite database, stop the server service before replacing files, then restart and roll back the payload if health verification fails.
