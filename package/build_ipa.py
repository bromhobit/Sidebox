#!/usr/bin/env python3
"""Package Sidebox into a clean, sideload-ready .ipa for stock iOS 15-18.5.

Signs the ARM64 iOS Mach-O executable with a standard ad-hoc signature WITHOUT any
private/jailbreak entitlements so isideload / Boxloader / AltServer / iLoader
can cleanly re-sign and install it with a free Apple ID on stock iOS.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import plistlib
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
SIDEBOX_DIR = PACKAGE_DIR.parent
OUTPUTS_DIR = SIDEBOX_DIR.parent
DEFAULT_CODESIGN_DIR = PACKAGE_DIR

BUNDLE_ID = "com.bromhobit.Sidebox"
APP_NAME = "Sidebox"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

FORBIDDEN_NAMES = {
    "apple-session.plist",
    "anisette_state",
    "config.plist",
    "pairingfile.plist",
    "altpairingfile.mobiledevicepairing",
    "embedded.mobileprovision",
}
FORBIDDEN_SUFFIXES = (".mobileprovision", ".mobiledevicepairing", ".p12", ".pem", ".key")


def load_codesign_module(codesign_dir: Path):
    codesign_file = codesign_dir / "codesign.py"
    if not codesign_file.is_file():
        raise RuntimeError(f"codesign.py not found in {codesign_dir}")
    if str(codesign_dir) not in sys.path:
        sys.path.insert(0, str(codesign_dir))
    import codesign  # type: ignore[import-not-found]

    return codesign


def verify_objdump_macho(binary: Path, *, require_signed: bool) -> None:
    proc = subprocess.run(
        ["llvm-objdump", "--macho", "--private-headers", str(binary)],
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"llvm-objdump failed on {binary}: {proc.stderr.strip()}")
    out = proc.stdout
    if "MH_MAGIC_64" not in out or "ARM64" not in out or "EXECUTE" not in out:
        raise RuntimeError(f"{binary} is not a 64-bit ARM64 Mach-O executable")
    if "platform ios" not in out:
        raise RuntimeError(f"{binary} does not target iOS (missing 'platform ios')")
    if require_signed and "LC_CODE_SIGNATURE" not in out:
        raise RuntimeError(f"{binary} is missing LC_CODE_SIGNATURE after signing")


def validate_info_plist(path: Path, version: str) -> tuple[dict, bytes]:
    info = plistlib.loads(path.read_bytes())
    if not isinstance(info, dict):
        raise RuntimeError(f"{path} must contain a plist dictionary")
    if info.get("CFBundleIdentifier") != BUNDLE_ID:
        raise RuntimeError(
            f"{path}: CFBundleIdentifier must be {BUNDLE_ID!r}, got {info.get('CFBundleIdentifier')!r}"
        )
    if info.get("CFBundleExecutable") != APP_NAME:
        raise RuntimeError(
            f"{path}: CFBundleExecutable must be {APP_NAME!r}, got {info.get('CFBundleExecutable')!r}"
        )
    if info.get("UIFileSharingEnabled") is not True:
        raise RuntimeError(f"{path}: UIFileSharingEnabled must be true")
    if info.get("LSSupportsOpeningDocumentsInPlace") is not True:
        raise RuntimeError(f"{path}: LSSupportsOpeningDocumentsInPlace must be true")
    local_net = info.get("NSLocalNetworkUsageDescription")
    if not isinstance(local_net, str) or not local_net.strip():
        raise RuntimeError(f"{path}: NSLocalNetworkUsageDescription must be a non-empty string")

    doc_types = info.get("CFBundleDocumentTypes")
    if not isinstance(doc_types, list) or not doc_types:
        raise RuntimeError(f"{path}: CFBundleDocumentTypes must declare .ipa document support")
    has_ipa_type = any(
        isinstance(entry, dict)
        and isinstance(entry.get("LSItemContentTypes"), list)
        and any(
            ct in ("com.apple.itunes.ipa", "public.archive", "public.data")
            for ct in entry["LSItemContentTypes"]
        )
        for entry in doc_types
    )
    if not has_ipa_type:
        raise RuntimeError(f"{path}: CFBundleDocumentTypes does not include an .ipa UTI")

    # Ensure no Assets.car-only CFBundleIconName breaks standalone PNG icons.
    for icons_key in ("CFBundleIcons", "CFBundleIcons~ipad"):
        sec = info.get(icons_key)
        if isinstance(sec, dict):
            primary = sec.get("CFBundlePrimaryIcon")
            if isinstance(primary, dict) and "CFBundleIconName" in primary:
                raise RuntimeError(
                    f"{path}: {icons_key}.CFBundlePrimaryIcon must not set CFBundleIconName without Assets.car"
                )

    info["CFBundleShortVersionString"] = version
    info["CFBundleVersion"] = version
    return info, plistlib.dumps(info, fmt=plistlib.FMT_XML, sort_keys=True)


def collect_app_icons(info_dict: dict, icons_dir: Path) -> list[tuple[str, bytes]]:
    names: list[str] = []

    def add_name(raw: object) -> None:
        if not isinstance(raw, str) or not raw:
            return
        if "/" in raw or "\\" in raw or raw in (".", ".."):
            raise RuntimeError(f"unsafe icon filename in Info.plist: {raw!r}")
        fname = raw if raw.endswith(".png") else f"{raw}.png"
        if fname not in names:
            names.append(fname)

    for item in info_dict.get("CFBundleIconFiles", []) or []:
        add_name(item)

    for icons_key in ("CFBundleIcons", "CFBundleIcons~ipad"):
        icons_section = info_dict.get(icons_key)
        if isinstance(icons_section, dict):
            primary = icons_section.get("CFBundlePrimaryIcon")
            if isinstance(primary, dict):
                for item in primary.get("CFBundleIconFiles", []) or []:
                    add_name(item)

    if icons_dir.is_dir():
        for png in sorted(icons_dir.glob("AppIcon*.png")):
            if png.is_file() and png.name not in names:
                names.append(png.name)

    resolved: list[tuple[str, bytes]] = []
    for fname in names:
        candidate = icons_dir / fname
        if candidate.is_file():
            data = candidate.read_bytes()
            if not data.startswith(PNG_SIGNATURE):
                raise RuntimeError(f"icon {candidate} is not a valid PNG")
            resolved.append((fname, data))
        else:
            stem = fname[:-4]
            matched_variant = False
            for suffix in ("@2x.png", "@3x.png"):
                vname = f"{stem}{suffix}"
                vpath = icons_dir / vname
                if vpath.is_file():
                    matched_variant = True
                    if all(existing != vname for existing, _ in resolved):
                        vdata = vpath.read_bytes()
                        if not vdata.startswith(PNG_SIGNATURE):
                            raise RuntimeError(f"icon {vpath} is not a valid PNG")
                        resolved.append((vname, vdata))
            if not matched_variant:
                raise RuntimeError(f"Info.plist references missing icon {fname} in {icons_dir}")

    if not resolved:
        raise RuntimeError(f"no AppIcon*.png files found in {icons_dir}")

    resolved.sort(key=lambda pair: pair[0])
    return resolved


def _check_safe_bundle_entry(name: str) -> None:
    base = Path(name).name.lower()
    if base in FORBIDDEN_NAMES or any(base.endswith(sfx) for sfx in FORBIDDEN_SUFFIXES):
        raise RuntimeError(f"refusing to bundle sensitive/disallowed file into IPA: {name}")


def build_ipa_bytes(
    *,
    app_binary: bytes,
    info_plist: bytes,
    icons: list[tuple[str, bytes]],
) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for dirname in ("Payload/", f"Payload/{APP_NAME}.app/"):
            dinfo = zipfile.ZipInfo(dirname)
            dinfo.date_time = (2026, 1, 1, 0, 0, 0)
            dinfo.create_system = 3
            dinfo.external_attr = (0o040755 << 16) | 0x10
            zf.writestr(dinfo, b"")

        entries: list[tuple[str, bytes, int]] = [
            (f"Payload/{APP_NAME}.app/{APP_NAME}", app_binary, 0o755),
            (f"Payload/{APP_NAME}.app/Info.plist", info_plist, 0o644),
        ]
        for icon_name, icon_bytes in icons:
            entries.append((f"Payload/{APP_NAME}.app/{icon_name}", icon_bytes, 0o644))

        for name, data, mode in entries:
            _check_safe_bundle_entry(name)
            zinfo = zipfile.ZipInfo(name)
            zinfo.date_time = (2026, 1, 1, 0, 0, 0)
            zinfo.create_system = 3
            zinfo.external_attr = (0o100000 | mode) << 16
            zinfo.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(zinfo, data)

    return buf.getvalue()


def write_atomic(dest: Path, data: bytes) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{dest.name}.", dir=dest.parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, dest)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def run_inspect_ipa(core_bin: Path, ipa_path: Path) -> dict:
    proc = subprocess.run(
        [str(core_bin), "inspect-ipa", "--ipa", str(ipa_path), "--json"],
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Boxloader core inspect-ipa failed (rc={proc.returncode}): "
            f"{proc.stdout.strip()} {proc.stderr.strip()}"
        )
    parsed = json.loads(proc.stdout.strip())
    if not parsed.get("ok"):
        raise RuntimeError(f"inspect-ipa reported failure: {parsed}")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Ad-hoc sign (no private entitlements) and package Sidebox .ipa for stock iOS."
    )
    parser.add_argument("--binary", type=Path, required=True, help="Compiled ARM64 iOS Sidebox executable")
    parser.add_argument("--info-plist", type=Path, default=SIDEBOX_DIR / "Info.plist")
    parser.add_argument("--icons-dir", type=Path, default=SIDEBOX_DIR)
    parser.add_argument(
        "--codesign-dir",
        type=Path,
        default=DEFAULT_CODESIGN_DIR,
        help="Directory containing codesign.py",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUTS_DIR,
        help="Output .ipa file path or output directory (default: parent dir)",
    )
    parser.add_argument("--version", default="1.0.0", help="Semantic version major.minor.patch")
    parser.add_argument(
        "--inspect-core",
        type=Path,
        default=None,
        help="Optional path to Boxloader core CLI to run inspect-ipa verification",
    )
    parser.add_argument("--force", action="store_true", help="Overwrite existing output .ipa")
    args = parser.parse_args()

    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", args.version):
        parser.error("version must be numeric major.minor.patch")

    if args.output.suffix == ".ipa":
        ipa_path = args.output
    else:
        ipa_path = args.output / f"{APP_NAME}-{args.version}.ipa"

    if ipa_path.exists() and not args.force:
        raise FileExistsError(f"refusing to overwrite {ipa_path} (pass --force)")

    codesign = load_codesign_module(args.codesign_dir.resolve(strict=True))

    src_binary = args.binary.resolve(strict=True)
    if not src_binary.is_file() or src_binary.stat().st_size == 0:
        raise RuntimeError(f"invalid binary input: {src_binary}")
    verify_objdump_macho(src_binary, require_signed=False)

    info_dict, info_plist_bytes = validate_info_plist(args.info_plist.resolve(strict=True), args.version)
    icons = collect_app_icons(info_dict, args.icons_dir.resolve(strict=True))

    with tempfile.TemporaryDirectory(prefix="sidebox-stage-") as td:
        staged = Path(td) / APP_NAME
        backend = codesign.sign_macho_file(
            src_binary,
            staged,
            identifier=BUNDLE_ID,
            entitlements_path=None,  # Stock iOS free-Apple-ID clean: ZERO private entitlements!
            signer="builtin",
        )
        verify_objdump_macho(staged, require_signed=True)
        signed_bytes = staged.read_bytes()
        sig_info = codesign.verify_macho_signature(
            signed_bytes,
            expected_entitlements=None,
            require_der=False,
        )
        if sig_info.flags != codesign.CS_ADHOC:
            raise RuntimeError(f"unexpected CodeDirectory flags: 0x{sig_info.flags:x}")
        if sig_info.xml_entitlements is not None or sig_info.der_entitlements is not None:
            raise RuntimeError("Sidebox binary must not embed private/jailbreak entitlements")

    ipa_bytes = build_ipa_bytes(
        app_binary=signed_bytes,
        info_plist=info_plist_bytes,
        icons=icons,
    )
    write_atomic(ipa_path, ipa_bytes)

    print(
        f"Signed {APP_NAME} ({backend}, no private entitlements): ident={sig_info.identifier} "
        f"ver=0x{sig_info.version:x} flags=0x{sig_info.flags:x} "
        f"pages={sig_info.code_slots} cdhash={sig_info.cdhash_sha256}"
    )
    print(f"Icons bundled: {', '.join(name for name, _ in icons)}")
    print(f"IPA: {ipa_path} ({len(ipa_bytes)} bytes)")

    if args.inspect_core is not None:
        inspected = run_inspect_ipa(args.inspect_core.resolve(strict=True), ipa_path)
        print(f"inspect-ipa OK: {json.dumps(inspected, ensure_ascii=False)}")


if __name__ == "__main__":
    main()
