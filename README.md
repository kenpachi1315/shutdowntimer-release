# PisoNet Server Release

Public update channel for the PisoNet Windows server.

- Branch: `release/server`
- Server build: `0.29`
- Files are listed with SHA-256 checksums in `manifest.json`.

## OTA behavior

Admin → Server OTA checks this branch. An administrator explicitly starts installation. The server downloads only the manifest allowlist over HTTPS, verifies SHA-256 checksums, stages backups, stops the `PisoNetServer` service, replaces the server Python modules and admin UI, then restarts the service. It checks `/api/health`; if the new build does not become healthy, it restores the previous files. SQLite data, service configuration, logs, client installs, and Telegram settings are outside the release payload.

Build `0.29` adds the dedicated Server OTA page, Windows `C:\TEMP\PisoNetServerOTA` staging, Unix `/tmp/PisoNetServerOTA` staging, and manual recovery/rollback controls. It also removes the Policy application status panel. Servers earlier than build `0.18` do not have the OTA updater. Manually update those servers to build `0.19` once using these five files; later higher builds can be installed from the admin page. Servers already on `0.18` can install `0.19` directly from the admin page.
