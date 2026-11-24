#!/usr/bin/env python3
"""Apply a verified PisoNet server OTA package and roll back on failed startup."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path

ALLOWED_DESTINATIONS = {
    "server.py",
    "coin_signal_engine.py",
    "serial_coin_adapter.py",
    "server_update_worker.py",
    "web/admin_v2.html",
}


def log(root: Path, message: str) -> None:
    try:
        target = root / "logs" / "server-update.log"
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as stream:
            stream.write(f"{datetime.now().astimezone().isoformat(timespec='seconds')} {message}\n")
    except OSError:
        pass


def set_status(root: Path, build: str, state: str, message: str, backup: str = "") -> None:
    data = {
        "build": build,
        "state": state,
        "message": message[:500],
        "updated_at": time.time(),
        "backup": backup,
    }
    target = root / "server_update_status.json"
    temporary = target.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, target)


def verify_payload(stage: Path, manifest: dict) -> list[tuple[Path, Path]]:
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("Release manifest has no files")
    operations = []
    for source_name, item in files.items():
        if not isinstance(item, dict):
            raise ValueError("Invalid file entry in release manifest")
        destination = str(item.get("destination", ""))
        digest = str(item.get("sha256", ""))
        if destination not in ALLOWED_DESTINATIONS or source_name not in ALLOWED_DESTINATIONS:
            raise ValueError(f"Release manifest contains a disallowed path: {destination}")
        if not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
            raise ValueError(f"Release manifest has an invalid checksum for {source_name}")
        source = stage / destination
        if not source.is_file():
            raise FileNotFoundError(f"Staged release file is missing: {destination}")
        actual = hashlib.sha256(source.read_bytes()).hexdigest()
        if actual.lower() != digest.lower():
            raise ValueError(f"Checksum verification failed for {destination}")
        operations.append((source, Path(destination)))
    for required in ("server.py", "coin_signal_engine.py", "serial_coin_adapter.py", "server_update_worker.py", "web/admin_v2.html"):
        if not any(str(destination).replace("\\", "/") == required for _source, destination in operations):
            raise ValueError(f"Release manifest is missing required file: {required}")
    return operations


def service_installed() -> bool:
    if os.name != "nt":
        return False
    result = subprocess.run(["sc.exe", "query", "PisoNetServer"], capture_output=True, text=True, timeout=10)
    return result.returncode == 0


def service_state() -> int | None:
    result = subprocess.run(["sc.exe", "query", "PisoNetServer"], capture_output=True, text=True, timeout=10)
    match = re.search(r"STATE\s*:\s*(\d+)", result.stdout, re.IGNORECASE)
    return int(match.group(1)) if match else None


def wait_service_state(expected: int, timeout: int = 40) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if service_state() == expected:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def process_is_alive(pid: int) -> bool:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return ctypes.get_last_error() == 5  # Access denied means the process exists.
        try:
            code = wintypes.DWORD()
            return bool(kernel32.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        return False


def stop_server(service: bool, parent_pid: int) -> None:
    if service:
        result = subprocess.run(["sc.exe", "stop", "PisoNetServer"], capture_output=True, text=True, timeout=20)
        if result.returncode != 0 and service_state() != 1:
            raise RuntimeError("Could not stop PisoNetServer service: " + (result.stderr or result.stdout)[-300:])
        if not wait_service_state(1):
            raise RuntimeError("PisoNetServer did not stop in time")
        return
    try:
        os.kill(parent_pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.time() + 30
    while time.time() < deadline:
        if not process_is_alive(parent_pid): return
        time.sleep(0.25)
    raise RuntimeError("Server process did not stop in time")


def start_server(service: bool, root: Path) -> int | None:
    if service:
        result = subprocess.run(["sc.exe", "start", "PisoNetServer"], capture_output=True, text=True, timeout=20)
        if result.returncode != 0 and service_state() != 4:
            raise RuntimeError("Could not start PisoNetServer service: " + (result.stderr or result.stdout)[-300:])
        return None
    flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    if os.name == "nt":
        flags |= getattr(subprocess, "CREATE_NO_WINDOW", 0)
    process = subprocess.Popen(
        [sys.executable, "-u", str(root / "server.py")],
        cwd=str(root), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, close_fds=True, creationflags=flags,
        start_new_session=(os.name != "nt"),
    )
    return process.pid


def wait_healthy(build: str, port: int, timeout: int = 75) -> bool:
    deadline = time.time() + timeout
    url = f"http://127.0.0.1:{port}/api/health"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                data = json.loads(response.read().decode("utf-8"))
            if data.get("ok") and str(data.get("build")) == build:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def apply_files(root: Path, stage: Path, operations: list[tuple[Path, Path]], backup: Path) -> list[Path]:
    changed = []
    for source, relative in operations:
        destination = root / relative
        if destination.resolve().parent != (root / relative).parent.resolve():
            raise ValueError("Release destination escaped the server directory")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            saved = backup / relative
            saved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(destination, saved)
        os.replace(source, destination)
        changed.append(relative)
    cache = root / "__pycache__"
    if cache.is_dir():
        for module in ("server", "coin_signal_engine", "serial_coin_adapter", "server_update_worker"):
            for stale in cache.glob(module + ".*.pyc"):
                stale.unlink(missing_ok=True)
    return changed


def rollback(root: Path, backup: Path, changed: list[Path]) -> None:
    for relative in reversed(changed):
        destination = root / relative
        saved = backup / relative
        if saved.is_file():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(saved, destination.with_suffix(destination.suffix + ".rollback"))
            os.replace(destination.with_suffix(destination.suffix + ".rollback"), destination)
        else:
            destination.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--stage", required=True, type=Path)
    parser.add_argument("--build", required=True)
    parser.add_argument("--previous-build", required=True)
    parser.add_argument("--parent-pid", required=True, type=int)
    parser.add_argument("--rollback-backup", type=Path, default=None)
    args = parser.parse_args()
    root, stage = args.root.resolve(), args.stage.resolve()
    backup = root / "backups" / ("server-ota-" + re.sub(r"[^0-9A-Za-z_.-]", "_", args.build) + "-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    changed: list[Path] = []
    active_pid = args.parent_pid
    server_stopped = False
    service = service_installed()
    port = int(os.environ.get("PISONET_PORT", "3210"))
    try:
        if args.rollback_backup is not None:
            backup=args.rollback_backup.resolve()
            if backup.parent!=(root/'backups').resolve() or not backup.is_dir():
                raise ValueError('Rollback backup is outside the server backup directory')
            changed=[Path(relative) for relative in ALLOWED_DESTINATIONS if (backup/relative).is_file()]
            if Path('server.py') not in changed:
                raise ValueError('Rollback backup does not contain server.py')
            saved_server=(backup/'server.py').read_text(encoding='utf-8',errors='replace')
            match=re.search(r"(?m)^SERVER_BUILD\s*=\s*['\"]([^'\"]+)['\"]",saved_server)
            if not match or match.group(1)!=args.build:
                raise ValueError('Rollback backup build does not match the requested target')
            set_status(root,args.build,'stopping','Stopping PisoNet before manual rollback.',str(backup))
            log(root,f'Manual rollback to build {args.build}: stopping service={service}; backup={backup}.')
            stop_server(service,args.parent_pid);server_stopped=True
            set_status(root,args.build,'installing','Restoring the selected server backup.',str(backup))
            rollback(root,backup,changed)
            active_pid=start_server(service,root) or args.parent_pid;server_stopped=False
            healthy=wait_healthy(args.build,port,timeout=75)
            state='complete' if healthy else 'failed'
            message=(f'Manual rollback to build {args.build} completed and passed its health check.' if healthy else f'Manual rollback to build {args.build} was applied, but health check did not pass.')
            set_status(root,args.build,state,message,str(backup))
            log(root,f'Manual rollback to build {args.build}: health_check={healthy}.')
            return 0 if healthy else 1
        manifest = json.loads((stage / "manifest.json").read_text(encoding="utf-8"))
        if str(manifest.get("build")) != args.build:
            raise ValueError("Staged server manifest build does not match the requested build")
        operations = verify_payload(stage / "payload", manifest)
        set_status(root, args.build, "stopping", "Stopping the PisoNet server for the update.")
        log(root, f"Server OTA build {args.build}: stopping service={service}.")
        stop_server(service, args.parent_pid)
        server_stopped = True
        set_status(root, args.build, "installing", "Installing verified server files.")
        changed = apply_files(root, stage / "payload", operations, backup)
        active_pid = start_server(service, root) or args.parent_pid
        server_stopped = False
        if wait_healthy(args.build, port):
            set_status(root, args.build, "complete", f"Server build {args.build} installed and responding.", str(backup))
            log(root, f"Server OTA build {args.build}: completed; backup={backup}.")
            return 0

        set_status(root, args.build, "rollback", "Updated server did not pass its health check; restoring previous files.", str(backup))
        log(root, f"Server OTA build {args.build}: health check failed; rolling back.")
        stop_server(service, active_pid)
        server_stopped = True
        rollback(root, backup, changed)
        start_server(service, root)
        server_stopped = False
        restored = wait_healthy(args.previous_build, port, timeout=75)
        message = "Update failed; previous files restored."
        if not restored:
            message += " The service is restarting; check server logs."
        set_status(root, args.build, "failed", message, str(backup))
        log(root, f"Server OTA build {args.build}: rollback completed; healthy={restored}.")
        return 1
    except Exception as exc:
        if server_stopped:
            try:
                try:
                    stop_server(service, active_pid)
                except Exception as stop_exc:
                    log(root, f"Server OTA rollback stop warning: {stop_exc}")
                if changed:
                    rollback(root, backup, changed)
                start_server(service, root)
                server_stopped = False
                log(root, f"Server OTA build {args.build}: restored original files after apply error.")
            except Exception as rollback_exc:
                log(root, f"Server OTA rollback error: {type(rollback_exc).__name__}: {rollback_exc}")
        log(root, f"Server OTA build {args.build}: failed: {type(exc).__name__}: {exc}")
        set_status(root, args.build, "failed", f"Update failed: {type(exc).__name__}: {exc}", str(backup) if backup.exists() else "")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
