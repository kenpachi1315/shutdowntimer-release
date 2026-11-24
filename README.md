# PisoNet Server Release

Public update channel for the PisoNet Windows server.

- Branch: `release/server`
- Server build: `0.18`
- Files are listed with SHA-256 checksums in `manifest.json`.

## OTA behavior

Admin → System settings → Server OTA checks this branch. Install downloads each manifest-listed file over HTTPS, verifies its SHA-256, stages a backup, stops the `PisoNetServer` service, replaces only the server Python modules and admin UI, then restarts the service. It checks `/api/health`; on a failed health check, it restores the previous files. The SQLite database, service configuration, logs, client installs, and Telegram settings are not part of the payload.

Build `0.18` adds the OTA installer. A production server must first be manually updated to build `0.18`; later builds can be installed from the admin page.
