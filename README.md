# PisoNet Server Release

Public update channel for the PisoNet Windows server.

- Branch: `release/server`
- Server build: `0.19`
- Files are listed with SHA-256 checksums in `manifest.json`.

## OTA behavior

Admin → System settings → Server OTA checks this branch. An administrator explicitly starts installation. The server downloads only the manifest allowlist over HTTPS, verifies SHA-256 checksums, stages backups, stops the `PisoNetServer` service, replaces the server Python modules and admin UI, then restarts the service. It checks `/api/health`; if the new build does not become healthy, it restores the previous files. SQLite data, service configuration, logs, client installs, and Telegram settings are outside the release payload.

Build `0.19` adds the admin OTA UI and verified GitHub update flow. A production server on build `0.18` must be updated manually once with these five files; subsequent higher builds can be installed from the admin page.
