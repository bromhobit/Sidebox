#!/usr/bin/env python3
"""Unit tests for sidebox/package/build_ipa.py."""

from __future__ import annotations

import plistlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
REPO_DIR = PACKAGE_DIR.parent
CODESIGN_DIR = PACKAGE_DIR
SAMPLE_ARM64_IOS_BIN = Path(os.environ.get("SIDEBOX_TEST_IOS_BINARY", "/nonexistent/Sidebox"))

sys.path.insert(0, str(PACKAGE_DIR))
sys.path.insert(0, str(CODESIGN_DIR))
import build_ipa  # noqa: E402
import codesign  # noqa: E402


def _make_png() -> bytes:
    def chunk(tag: bytes, payload: bytes) -> bytes:
        return struct.pack(">I", len(payload)) + tag + payload + struct.pack(
            ">I", zlib.crc32(tag + payload) & 0xFFFFFFFF
        )

    ihdr = struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00" + b"\x10\x20\x30" * 2 + b"\x00" + b"\x10\x20\x30" * 2)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def _sample_info_plist() -> dict:
    return {
        "CFBundleIdentifier": "com.bromhobit.Sidebox",
        "CFBundleExecutable": "Sidebox",
        "CFBundleName": "Sidebox",
        "CFBundleDisplayName": "Sidebox",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": "1.0.0",
        "CFBundleVersion": "1.0.0",
        "LSRequiresIPhoneOS": True,
        "MinimumOSVersion": "15.0",
        "UIFileSharingEnabled": True,
        "LSSupportsOpeningDocumentsInPlace": True,
        "NSLocalNetworkUsageDescription": "Sidebox подключается к локальному туннелю 10.7.0.1.",
        "CFBundleDocumentTypes": [
            {
                "CFBundleTypeName": "iOS App",
                "CFBundleTypeRole": "Viewer",
                "LSHandlerRank": "Alternate",
                "LSItemContentTypes": ["com.apple.itunes.ipa"],
            }
        ],
        "CFBundleIconFiles": [
            "AppIcon60x60@2x.png",
            "AppIcon60x60@3x.png",
            "AppIcon76x76@2x.png",
        ],
        "CFBundleIcons": {
            "CFBundlePrimaryIcon": {
                "CFBundleIconFiles": ["AppIcon60x60"],
            }
        },
        "CFBundleIcons~ipad": {
            "CFBundlePrimaryIcon": {
                "CFBundleIconFiles": ["AppIcon60x60", "AppIcon76x76"],
            }
        },
    }


class SideboxBuildIpaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="sidebox-pkg-test-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        for name in ("AppIcon60x60@2x.png", "AppIcon60x60@3x.png", "AppIcon76x76@2x.png"):
            (self.tmp / name).write_bytes(_make_png())
        (self.tmp / "Info.plist").write_bytes(plistlib.dumps(_sample_info_plist()))

    def test_repo_branding_and_info_plist_clean(self) -> None:
        info_path = REPO_DIR / "Info.plist"
        info = plistlib.loads(info_path.read_bytes())
        self.assertEqual(info.get("CFBundleIdentifier"), "com.bromhobit.Sidebox")
        self.assertEqual(info.get("CFBundleExecutable"), "Sidebox")
        self.assertEqual(info.get("CFBundleDisplayName"), "Sidebox")
        self.assertEqual(info.get("CFBundleName"), "Sidebox")
        self.assertEqual(info.get("CFBundleShortVersionString"), "1.0.0")
        self.assertEqual(info.get("CFBundleVersion"), "1.0.0")

        ut_decls = info.get("UTImportedTypeDeclarations") or []
        ut_ids = [d.get("UTTypeIdentifier") for d in ut_decls if isinstance(d, dict)]
        self.assertIn("com.bromhobit.sidebox.mobiledevicepairing", ut_ids)

        files_to_check = [
            info_path,
            REPO_DIR / "Cargo.toml",
            REPO_DIR / "README.md",
            REPO_DIR / "package" / "build_ipa.py",
            *sorted((REPO_DIR / "src").glob("*.rs")),
        ]
        forbidden = ("org.codex", "DopamineLoader", "dopamine-renew")
        for fpath in files_to_check:
            text = fpath.read_text(encoding="utf-8")
            for needle in forbidden:
                self.assertNotIn(
                    needle.lower(),
                    text.lower(),
                    f"Legacy token {needle!r} found in {fpath}",
                )

    def test_validate_info_plist_rejects_missing_local_network_or_file_sharing(self) -> None:
        bad = _sample_info_plist()
        bad["UIFileSharingEnabled"] = False
        bad_path = self.tmp / "BadInfo.plist"
        bad_path.write_bytes(plistlib.dumps(bad))
        with self.assertRaises(RuntimeError):
            build_ipa.validate_info_plist(bad_path, "1.0.0")

        bad2 = _sample_info_plist()
        del bad2["NSLocalNetworkUsageDescription"]
        bad_path.write_bytes(plistlib.dumps(bad2))
        with self.assertRaises(RuntimeError):
            build_ipa.validate_info_plist(bad_path, "1.0.0")

    def test_end_to_end_builds_clean_no_entitlement_ipa(self) -> None:
        if not SAMPLE_ARM64_IOS_BIN.is_file():
            self.skipTest("sample ARM64 iOS Mach-O not present")

        out_ipa = self.tmp / "Sidebox-1.0.0.ipa"
        proc = subprocess.run(
            [
                sys.executable,
                str(PACKAGE_DIR / "build_ipa.py"),
                "--binary",
                str(SAMPLE_ARM64_IOS_BIN),
                "--info-plist",
                str(self.tmp / "Info.plist"),
                "--icons-dir",
                str(self.tmp),
                "--output",
                str(out_ipa),
                "--version",
                "1.0.0",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(out_ipa.is_file())

        with zipfile.ZipFile(out_ipa) as zf:
            names = zf.namelist()
            self.assertIn("Payload/Sidebox.app/Sidebox", names)
            self.assertIn("Payload/Sidebox.app/Info.plist", names)
            self.assertIn("Payload/Sidebox.app/AppIcon60x60@3x.png", names)
            exe_info = zf.getinfo("Payload/Sidebox.app/Sidebox")
            self.assertEqual((exe_info.external_attr >> 16) & 0o7777, 0o755)
            plist_info = zf.getinfo("Payload/Sidebox.app/Info.plist")
            self.assertEqual((plist_info.external_attr >> 16) & 0o7777, 0o644)

            exe_bytes = zf.read("Payload/Sidebox.app/Sidebox")
            sig = codesign.verify_macho_signature(exe_bytes, expected_entitlements=None, require_der=False)
            self.assertEqual(sig.identifier, "com.bromhobit.Sidebox")
            self.assertEqual(sig.flags, codesign.CS_ADHOC)
            self.assertIsNone(sig.xml_entitlements)
            self.assertIsNone(sig.der_entitlements)

    def test_rejects_elf_binary(self) -> None:
        proc = subprocess.run(
            [
                sys.executable,
                str(PACKAGE_DIR / "build_ipa.py"),
                "--binary",
                "/usr/bin/true",
                "--info-plist",
                str(self.tmp / "Info.plist"),
                "--icons-dir",
                str(self.tmp),
                "--output",
                str(self.tmp / "bad.ipa"),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
