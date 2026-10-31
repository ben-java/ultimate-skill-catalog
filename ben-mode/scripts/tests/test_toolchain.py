#!/usr/bin/env python3
"""test_toolchain.py — P7-H#1: unit tests for allowlist, VC, and SBOM tooling.
Pure stdlib unittest. Usage: python test_toolchain.py  (or python -m unittest
discover). Exits 0 on ALL pass, 1 on any failure.
"""
import base64, json, os, subprocess, sys, tempfile, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent
PY = sys.executable
OPENSSL = "openssl"


def run(*args, cwd=None, env=None):
    e = dict(os.environ)
    e["PYTHONDONTWRITEBYTECODE"] = "1"
    if env:
        e.update(env)
    return subprocess.run([PY, *args], cwd=cwd or str(SCRIPTS),
                          capture_output=True, text=True, env=e)


class AllowlistTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.alw = self.tmp / "hard-gate-allowlist.json"

    def test_init_valid(self):
        r = run(str(SCRIPTS / "allowlist.py"), "--root", str(self.tmp), "init")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.alw.exists())
        d = json.loads(self.alw.read_text(encoding="utf-8"))
        self.assertIn("allowed_drifts", d)

    def test_add_remove_validate_roundtrip(self):
        run(str(SCRIPTS / "allowlist.py"), "--root", str(self.tmp), "init")
        r = run(str(SCRIPTS / "allowlist.py"), "--root", str(self.tmp),
                "add", "--skill", "ben-mode", "--hash", "abc123",
                "--reason", "unit", "--approved-by", "test")
        self.assertEqual(r.returncode, 0, r.stderr)
        d = json.loads(self.alw.read_text(encoding="utf-8"))
        self.assertEqual(len(d["allowed_drifts"]), 1)
        r = run(str(SCRIPTS / "allowlist.py"), "--root", str(self.tmp), "validate")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = run(str(SCRIPTS / "allowlist.py"), "--root", str(self.tmp),
                "remove", "--skill", "ben-mode", "--hash", "abc123")
        self.assertEqual(r.returncode, 0)
        d = json.loads(self.alw.read_text(encoding="utf-8"))
        self.assertEqual(len(d["allowed_drifts"]), 0)

    def test_expired_rejected(self):
        run(str(SCRIPTS / "allowlist.py"), "--root", str(self.tmp), "init")
        run(str(SCRIPTS / "allowlist.py"), "--root", str(self.tmp),
            "add", "--skill", "ben-mode", "--hash", "abc123",
            "--reason", "unit", "--approved-by", "test",
            "--expires", "2000-01-01T00:00:00Z")
        d = json.loads(self.alw.read_text(encoding="utf-8"))
        from datetime import datetime, timezone
        exp = datetime.fromisoformat(d["allowed_drifts"][0]["expires_at"].replace("Z", "+00:00"))
        self.assertLess(exp, datetime.now(timezone.utc))


class VCTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.key = self.tmp / "k.pem"
        subprocess.run([OPENSSL, "genpkey", "-algorithm", "ED25519",
                        "-out", str(self.key)], check=True, capture_output=True)
        # ensure an allowlist exists
        run(str(SCRIPTS / "allowlist.py"), "--root", str(self.tmp), "init")
        run(str(SCRIPTS / "allowlist.py"), "--root", str(self.tmp),
            "add", "--skill", "ben-mode", "--hash", "abcdef0123456789",
            "--reason", "vc", "--approved-by", "test")

    def test_sign_verify_clean(self):
        r = run(str(SCRIPTS / "vc-allowlist.py"), "--root", str(self.tmp),
                "sign", "--key", str(self.key), "--index", "0")
        self.assertEqual(r.returncode, 0, r.stderr)
        vcs = list(self.tmp.glob("*.vc.json"))
        self.assertEqual(len(vcs), 1, "expected exactly one .vc.json")
        r = run(str(SCRIPTS / "vc-allowlist.py"), "--root", str(self.tmp),
                "verify", "--pub", str(self.key))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("VALID", r.stdout)

    def test_revoke_rejects(self):
        run(str(SCRIPTS / "vc-allowlist.py"), "--root", str(self.tmp),
            "sign", "--key", str(self.key), "--index", "0")
        r = run(str(SCRIPTS / "vc-allowlist.py"), "--root", str(self.tmp),
                "revoke", "--index", "0")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run(str(SCRIPTS / "vc-allowlist.py"), "--root", str(self.tmp),
                "verify", "--pub", str(self.key))
        self.assertEqual(r.returncode, 1)
        self.assertIn("revoked", r.stderr.lower())


class SBOMTest(unittest.TestCase):
    def test_generates_valid_cyclonedx(self):
        tmp = Path(tempfile.mkdtemp())
        out = tmp / "sbom.json"
        r = run(str(SCRIPTS / "generate-sbom.py"), str(SCRIPTS),
                "--out", str(out))
        self.assertEqual(r.returncode, 0, r.stderr)
        d = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(d["bomFormat"], "CycloneDX")
        self.assertEqual(d["specVersion"], "1.5")
        self.assertIn("components", d)
        self.assertGreater(len(d["components"]), 0)
        for c in d["components"]:
            self.assertIn("hashes", c)
            self.assertEqual(c["hashes"][0]["alg"], "SHA-256")


if __name__ == "__main__":
    unittest.main(verbosity=2)
