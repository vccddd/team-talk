#!/usr/bin/env python3
"""Pack, upload, and unpack Git-ignored client build inputs for private CI repositories.

Security boundary:
- Intended ONLY for standalone private GitHub repositories (`visibility == PRIVATE`).
- Never includes server-only secrets (`*.p8`, `*private-key*`, `*.jks`, SSH/DB/TURN secrets).
- Refuses to materialize any private bundle or Android keystore when `GITHUB_REPO_PRIVATE`
  is not `"true"`.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path, PurePosixPath

CHUNK_ENV_PREFIX = "TEAMTALK_CLIENT_BUNDLE_B64_"
ANDROID_KEYSTORE_ENV = "ANDROID_KEYSTORE_BASE64"
DEFAULT_CHUNK_SIZE = 45_000
MAX_CHUNKS = 16
MAX_UNCOMPRESSED_BYTES = 10 * 1024 * 1024
ALLOWED_SECRETS_KEYS = frozenset({"appKey", "appSecret"})
FORBIDDEN_FRAGMENTS = (".p8", "private-key", ".jks", ".keystore", ".pfx", ".p12")


def _has_forbidden_fragment(rel_path: str) -> bool:
    lowered = rel_path.lower()
    return any(fragment in lowered for fragment in FORBIDDEN_FRAGMENTS)


def is_allowed_client_path(rel_path: str) -> bool:
    """Allow only Git-ignored client build override paths."""
    if not rel_path or "\x00" in rel_path or "\\" in rel_path or rel_path.startswith("/"):
        return False
    posix = PurePosixPath(rel_path)
    parts = posix.parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        return False
    if _has_forbidden_fragment(rel_path):
        return False
    if parts == ("client", "ios", "Config", "Signing.local.xcconfig"):
        return True
    if len(parts) == 2 and parts[0] == "gradle" and posix.suffix == ".secrets":
        return True
    if len(parts) >= 3 and parts[0] == "buildSrc" and parts[1] == "deployment-local":
        if rel_path == "buildSrc/deployment-local/tcp-tls/certificate.pem":
            return True
        if posix.suffix in (".kt", ".aar", ".secrets"):
            return True
    return False


def sanitize_secrets_bytes(raw: bytes) -> bytes | None:
    """Keep only Android client build properties (`appKey` / `appSecret`) from a .secrets file."""
    text = raw.decode("utf-8")
    kept_lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("!"):
            continue
        eq_idx = stripped.find("=")
        colon_idx = stripped.find(":")
        candidates = [idx for idx in (eq_idx, colon_idx) if idx != -1]
        if not candidates:
            continue
        sep_idx = min(candidates)
        key = stripped[:sep_idx].strip()
        if key in ALLOWED_SECRETS_KEYS:
            kept_lines.append(stripped)
    if not kept_lines:
        return None
    return ("\n".join(kept_lines) + "\n").encode("utf-8")


def validate_unpacked_file(rel_path: str, data: bytes) -> None:
    """Validate unpacked content so server-only credentials or private keys are never accepted."""
    if rel_path.endswith(".pem") and b"PRIVATE KEY" in data:
        raise RuntimeError(f"Refusing PEM containing a private key in {rel_path}")
    if rel_path.endswith(".secrets"):
        text = data.decode("utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("!"):
                continue
            eq_idx = stripped.find("=")
            colon_idx = stripped.find(":")
            candidates = [idx for idx in (eq_idx, colon_idx) if idx != -1]
            if not candidates:
                raise RuntimeError(f"Unrecognized line in {rel_path}")
            sep_idx = min(candidates)
            key = stripped[:sep_idx].strip()
            if key not in ALLOWED_SECRETS_KEYS:
                raise RuntimeError(f"Forbidden non-client secret key '{key}' in {rel_path}")


def collect_client_files(source_repo: Path) -> list[tuple[str, bytes]]:
    """Collect Git-ignored client configuration files from a private local clone."""
    deployment_kt = source_repo / "buildSrc" / "deployment-local" / "Deployment.kt"
    if not deployment_kt.is_file():
        raise RuntimeError(f"Required private config not found: {deployment_kt}")

    collected: dict[str, bytes] = {}
    local_dir = source_repo / "buildSrc" / "deployment-local"
    for path in sorted(local_dir.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        rel = path.relative_to(source_repo).as_posix()
        if not is_allowed_client_path(rel):
            continue
        raw = path.read_bytes()
        if rel.endswith(".secrets"):
            sanitized = sanitize_secrets_bytes(raw)
            if sanitized is None:
                continue
            raw = sanitized
        validate_unpacked_file(rel, raw)
        collected[rel] = raw

    gradle_dir = source_repo / "gradle"
    if gradle_dir.is_dir():
        for path in sorted(gradle_dir.glob("*.secrets")):
            if not path.is_file() or path.is_symlink():
                continue
            rel = path.relative_to(source_repo).as_posix()
            if not is_allowed_client_path(rel):
                continue
            sanitized = sanitize_secrets_bytes(path.read_bytes())
            if sanitized is not None:
                collected[rel] = sanitized

    xcconfig = source_repo / "client" / "ios" / "Config" / "Signing.local.xcconfig"
    if xcconfig.is_file() and not xcconfig.is_symlink():
        collected["client/ios/Config/Signing.local.xcconfig"] = xcconfig.read_bytes()

    return sorted(collected.items(), key=lambda item: item[0])


def pack_client_bundle(entries: list[tuple[str, bytes]], chunk_size: int = DEFAULT_CHUNK_SIZE) -> list[str]:
    """Create a deterministic tar.gz archive in memory and split base64 into fixed-size chunks."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as tf:
            for rel_path, data in entries:
                if not is_allowed_client_path(rel_path):
                    raise RuntimeError(f"Disallowed client bundle entry: {rel_path}")
                validate_unpacked_file(rel_path, data)
                info = tarfile.TarInfo(name=rel_path)
                info.size = len(data)
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mode = 0o644 if rel_path.endswith((".aar", ".pem")) else 0o600
                tf.addfile(info, io.BytesIO(data))
    archive_bytes = buf.getvalue()
    if len(archive_bytes) > MAX_UNCOMPRESSED_BYTES:
        raise RuntimeError("Compressed client bundle exceeds size limit")
    b64 = base64.b64encode(archive_bytes).decode("ascii")
    chunks = [b64[i : i + chunk_size] for i in range(0, len(b64), chunk_size)]
    if len(chunks) > MAX_CHUNKS:
        raise RuntimeError(
            f"Client bundle requires {len(chunks)} chunks, exceeding MAX_CHUNKS={MAX_CHUNKS}. "
            "Remove unnecessary vendor binaries or raise MAX_CHUNKS.",
        )
    return chunks


def unpack_from_env(repo_root: Path, env: dict[str, str] | None = None) -> list[Path]:
    """Validate visibility guard and extract client bundle chunks into Git-ignored paths."""
    environ = os.environ if env is None else env
    chunks: list[str] = []
    seen_gap = False
    for index in range(1, MAX_CHUNKS + 1):
        val = environ.get(f"{CHUNK_ENV_PREFIX}{index}", "").strip()
        if not val:
            seen_gap = True
        else:
            if seen_gap:
                raise RuntimeError(
                    f"Non-contiguous chunk {CHUNK_ENV_PREFIX}{index} without preceding chunk",
                )
            chunks.append(val)

    has_keystore = bool(environ.get(ANDROID_KEYSTORE_ENV, "").strip())
    if not chunks and not has_keystore:
        print("No private client bundle configured; using repository default Deployment.kt.")
        return []

    is_private = environ.get("GITHUB_REPO_PRIVATE", "").strip().lower() == "true"
    if not is_private:
        raise RuntimeError(
            "Security guard: refusing to materialize private client secrets or Android keystore "
            "in a non-private repository (GITHUB_REPO_PRIVATE != 'true').",
        )

    if not chunks:
        print("Android keystore secret detected on private repo; no Deployment.kt bundle chunks set.")
        return []

    raw_b64 = "".join(chunks)
    archive_bytes = base64.b64decode(raw_b64, validate=True)
    written: list[Path] = []
    total_size = 0
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                raise RuntimeError(f"Refusing non-regular tar entry: {member.name}")
            if not is_allowed_client_path(member.name):
                raise RuntimeError(f"Refusing disallowed tar entry: {member.name}")
            if member.size < 0:
                raise RuntimeError(f"Invalid member size for {member.name}")
            total_size += member.size
            if total_size > MAX_UNCOMPRESSED_BYTES:
                raise RuntimeError("Unpacked client bundle exceeds 10 MiB limit")
            extracted = tf.extractfile(member)
            if extracted is None:
                raise RuntimeError(f"Cannot read tar entry: {member.name}")
            data = extracted.read()
            validate_unpacked_file(member.name, data)
            target = (repo_root / member.name).resolve()
            resolved_root = repo_root.resolve()
            if resolved_root not in target.parents:
                raise RuntimeError(f"Target escapes repository root: {member.name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            os.chmod(target, 0o644 if member.name.endswith((".aar", ".pem")) else 0o600)
            written.append(target)

    print(f"Materialized {len(written)} private client build file(s).")
    return written


def verify_private_github_repo(github_repo: str) -> None:
    result = subprocess.run(
        ["gh", "repo", "view", github_repo, "--json", "isPrivate,visibility"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"Failed to inspect repository {github_repo}")
    meta = json.loads(result.stdout)
    if not (meta.get("isPrivate") is True and meta.get("visibility") == "PRIVATE"):
        raise RuntimeError(
            f"Refusing upload: repository {github_repo} is not PRIVATE (visibility={meta.get('visibility')}).",
        )


def upload_bundle(source_repo: Path, github_repo: str, chunk_size: int, dry_run: bool) -> None:
    entries = collect_client_files(source_repo)
    chunks = pack_client_bundle(entries, chunk_size=chunk_size)
    if dry_run:
        print(f"[dry-run] Target repo: {github_repo}")
        print(f"[dry-run] Files ({len(entries)}):")
        for rel_path, data in entries:
            print(f"  - {rel_path} ({len(data)} bytes)")
        print(f"[dry-run] Chunks: {len(chunks)} (max {MAX_CHUNKS})")
        return

    verify_private_github_repo(github_repo)
    existing_proc = subprocess.run(
        ["gh", "secret", "list", "--repo", github_repo, "--json", "name"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if existing_proc.returncode != 0:
        raise RuntimeError(existing_proc.stderr.strip() or f"Failed to list secrets for {github_repo}")
    existing_names = {item["name"] for item in json.loads(existing_proc.stdout)}

    for index, chunk in enumerate(chunks, start=1):
        secret_name = f"{CHUNK_ENV_PREFIX}{index}"
        proc = subprocess.run(
            ["gh", "secret", "set", secret_name, "--repo", github_repo],
            input=chunk,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or f"Failed to set {secret_name}")

    for index in range(len(chunks) + 1, MAX_CHUNKS + 1):
        secret_name = f"{CHUNK_ENV_PREFIX}{index}"
        if secret_name in existing_names:
            subprocess.run(
                ["gh", "secret", "delete", secret_name, "--repo", github_repo],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )

    print(
        f"Uploaded {len(entries)} client build file(s) as {len(chunks)} secret chunk(s) to {github_repo}.",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage private client CI bundle secrets.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    unpack_cmd = subparsers.add_parser("unpack", help="Unpack client CI bundle from environment.")
    unpack_cmd.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root path.")

    upload_cmd = subparsers.add_parser("upload", help="Pack and upload client bundle to a private repo.")
    upload_cmd.add_argument("--source-repo", type=Path, required=True, help="Local private clone path.")
    upload_cmd.add_argument("--github-repo", required=True, help="Target private owner/repo slug.")
    upload_cmd.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE)
    upload_cmd.add_argument("--dry-run", action="store_true", help="Inspect bundle without uploading.")

    args = parser.parse_args(argv)
    try:
        if args.command == "unpack":
            unpack_from_env(args.root)
        elif args.command == "upload":
            upload_bundle(args.source_repo, args.github_repo, args.chunk_size, args.dry_run)
        return 0
    except (RuntimeError, ValueError, tarfile.TarError) as exc:
        print(f"private_client_ci_bundle error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
