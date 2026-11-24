#!/usr/bin/env python3
"""Unit tests for private client CI bundle packing, filtering, and security guards."""

from __future__ import annotations

import base64
import gzip
import io
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import private_client_ci_bundle as bundle


class PrivateClientCiBundleTest(unittest.TestCase):
    def test_noop_when_no_bundle_or_keystore_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            written = bundle.unpack_from_env(Path(tmp), env={"GITHUB_REPO_PRIVATE": "false"})
            self.assertEqual(written, [])

    def test_refuses_bundle_or_keystore_on_public_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError, "non-private repository"):
                bundle.unpack_from_env(
                    Path(tmp),
                    env={
                        "GITHUB_REPO_PRIVATE": "false",
                        "TEAMTALK_CLIENT_BUNDLE_B64_1": "AAAA",
                    },
                )
            with self.assertRaisesRegex(RuntimeError, "non-private repository"):
                bundle.unpack_from_env(
                    Path(tmp),
                    env={
                        "GITHUB_REPO_PRIVATE": "",
                        "ANDROID_KEYSTORE_BASE64": "AAAA",
                    },
                )

    def test_collect_strips_server_secrets_and_private_keys(self) -> None:
        with tempfile.TemporaryDirectory() as src_dir, tempfile.TemporaryDirectory() as dst_dir:
            src = Path(src_dir)
            (src / "buildSrc" / "deployment-local" / "apns").mkdir(parents=True)
            (src / "buildSrc" / "deployment-local" / "tcp-tls").mkdir(parents=True)
            (src / "buildSrc" / "deployment-local" / "oem").mkdir(parents=True)
            (src / "gradle").mkdir(parents=True)
            (src / "client" / "ios" / "Config").mkdir(parents=True)

            (src / "buildSrc" / "deployment-local" / "Deployment.kt").write_text(
                "package deployment\n", encoding="utf-8",
            )
            (src / "buildSrc" / "deployment-local" / "apns" / "AuthKey.p8").write_text(
                "SECRET_P8", encoding="utf-8",
            )
            (src / "buildSrc" / "deployment-local" / "tcp-tls" / "certificate.pem").write_text(
                "-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n", encoding="utf-8",
            )
            (src / "buildSrc" / "deployment-local" / "tcp-tls" / "private-key.pem").write_text(
                "-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----\n", encoding="utf-8",
            )
            (src / "buildSrc" / "deployment-local" / "oem" / "oppo.aar").write_bytes(b"aar-bytes")
            (src / "buildSrc" / "deployment-local" / "deployment.secrets").write_text(
                "TURN_SECRET=top-secret-turn\nappSecret=client-oppo-secret\nADMIN_PASS=bad\n",
                encoding="utf-8",
            )
            (src / "gradle" / "oppo-push.secrets").write_text(
                "appKey=client-oppo-key\nappSecret=client-oppo-secret\nSERVER_MASTER_SECRET=bad\n",
                encoding="utf-8",
            )
            (src / "client" / "ios" / "Config" / "Signing.local.xcconfig").write_text(
                "DEVELOPMENT_TEAM = ABCDE12345\n", encoding="utf-8",
            )

            entries = bundle.collect_client_files(src)
            names = [name for name, _ in entries]
            self.assertEqual(
                names,
                [
                    "buildSrc/deployment-local/Deployment.kt",
                    "buildSrc/deployment-local/deployment.secrets",
                    "buildSrc/deployment-local/oem/oppo.aar",
                    "buildSrc/deployment-local/tcp-tls/certificate.pem",
                    "client/ios/Config/Signing.local.xcconfig",
                    "gradle/oppo-push.secrets",
                ],
            )

            chunks = bundle.pack_client_bundle(entries, chunk_size=128)
            self.assertGreaterEqual(len(chunks), 2)
            env = {"GITHUB_REPO_PRIVATE": "true"}
            for i, chunk in enumerate(chunks, start=1):
                env[f"{bundle.CHUNK_ENV_PREFIX}{i}"] = chunk

            dst = Path(dst_dir)
            bundle.unpack_from_env(dst, env=env)
            self.assertEqual(
                (dst / "buildSrc" / "deployment-local" / "deployment.secrets").read_text(encoding="utf-8"),
                "appSecret=client-oppo-secret\n",
            )
            self.assertEqual(
                (dst / "gradle" / "oppo-push.secrets").read_text(encoding="utf-8"),
                "appKey=client-oppo-key\nappSecret=client-oppo-secret\n",
            )
            self.assertFalse((dst / "buildSrc" / "deployment-local" / "apns" / "AuthKey.p8").exists())
            self.assertFalse((dst / "buildSrc" / "deployment-local" / "tcp-tls" / "private-key.pem").exists())
            self.assertEqual(os.stat(dst / "buildSrc" / "deployment-local" / "Deployment.kt").st_mode & 0o777, 0o600)

    def test_unpack_rejects_disallowed_paths_and_server_secret_keys(self) -> None:
        def build_raw_archive(name: str, payload: bytes) -> str:
            buf = io.BytesIO()
            with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
                with tarfile.open(fileobj=gz, mode="w") as tf:
                    info = tarfile.TarInfo(name=name)
                    info.size = len(payload)
                    tf.addfile(info, io.BytesIO(payload))
            return base64.b64encode(buf.getvalue()).decode("ascii")

        with tempfile.TemporaryDirectory() as tmp:
            bad_path_b64 = build_raw_archive("../evil.txt", b"x")
            with self.assertRaisesRegex(RuntimeError, "disallowed"):
                bundle.unpack_from_env(
                    Path(tmp),
                    env={"GITHUB_REPO_PRIVATE": "true", "TEAMTALK_CLIENT_BUNDLE_B64_1": bad_path_b64},
                )

            bad_p8_b64 = build_raw_archive("buildSrc/deployment-local/apns/AuthKey.p8", b"x")
            with self.assertRaisesRegex(RuntimeError, "disallowed"):
                bundle.unpack_from_env(
                    Path(tmp),
                    env={"GITHUB_REPO_PRIVATE": "true", "TEAMTALK_CLIENT_BUNDLE_B64_1": bad_p8_b64},
                )

            bad_secret_b64 = build_raw_archive(
                "buildSrc/deployment-local/deployment.secrets",
                b"TURN_SECRET=leak\n",
            )
            with self.assertRaisesRegex(RuntimeError, "Forbidden non-client secret key"):
                bundle.unpack_from_env(
                    Path(tmp),
                    env={"GITHUB_REPO_PRIVATE": "true", "TEAMTALK_CLIENT_BUNDLE_B64_1": bad_secret_b64},
                )


if __name__ == "__main__":
    unittest.main()
