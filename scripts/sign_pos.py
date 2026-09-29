"""Sign or verify the POS package manifest (docs/design.md, section 7.1).

Signing runs on the operator workstation only: the release key never reaches CI, so a compromised
GitHub account can't produce a package the POS machines accept. ``--check`` (CI, and the release job
before attaching anything) verifies the committed manifest and signature against ``pos/package``.

The manifest's ``version`` is the POS package's own, independent of the wheel version: it rises only
when the package files change, so a CLI-only release leaves the fleet's daily install a no-op.
"""

# Standard library imports
import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

POS = Path(__file__).resolve().parent.parent / "pos"
PACKAGE = POS / "package"
MANIFEST = POS / "manifest.json"
SIGNATURE = POS / "manifest.json.sig"
ALLOWED_SIGNERS = POS / "allowed_signers"
# Signature namespace and allowed_signers principal; Install-PosTunnel pins the same pair.
NAMESPACE = "pos-tunnel-release"


def package_hashes() -> dict[str, str]:
  """Return ``{file name: sha256}`` for every file in ``pos/package``.

  Hashes are of the working-tree bytes, which ``.gitattributes`` makes CRLF for ``.ps1`` on every
  platform; an LF file here means a checkout predating that rule, and would hash differently in CI.
  """
  hashes: dict[str, str] = {}
  for path in sorted(PACKAGE.iterdir()):
    data = path.read_bytes()
    if path.suffix == ".ps1" and b"\n" in data.replace(b"\r\n", b""):
      sys.exit(f"{path.name}: not CRLF; renormalize the checkout (git add --renormalize .)")
    hashes[path.name] = hashlib.sha256(data).hexdigest()
  return hashes


def check() -> None:
  """Exit non-zero unless the manifest matches the files and carries a valid signature."""
  if not (MANIFEST.exists() and SIGNATURE.exists() and ALLOWED_SIGNERS.exists()):
    sys.exit("pos/manifest.json, its .sig or pos/allowed_signers is missing: the package was never signed")
  manifest = json.loads(MANIFEST.read_bytes())
  if manifest["files"] != package_hashes():
    sys.exit("pos/package differs from pos/manifest.json: run `poe sign-pos`")
  verify = subprocess.run(
    ["ssh-keygen", "-Y", "verify", "-f", ALLOWED_SIGNERS, "-I", NAMESPACE, "-n", NAMESPACE, "-s", SIGNATURE],
    input=MANIFEST.read_bytes(),
    check=False,
  )
  if verify.returncode:
    sys.exit("pos/manifest.json.sig is not a valid signature by the key in pos/allowed_signers")


def sign(key: str) -> None:
  """Rewrite and re-sign the manifest if the package changed or no signature exists yet.

  Args:
    key: Path to the release signing private key.
  """
  old = json.loads(MANIFEST.read_bytes()) if MANIFEST.exists() else {"version": 0, "files": {}}
  hashes = package_hashes()
  if hashes == old["files"] and SIGNATURE.exists():
    print(f"pos package unchanged at version {old['version']}")
    return
  manifest = {"version": old["version"] + (hashes != old["files"]), "files": hashes}
  # Bytes, not write_text: text mode on Windows would write CRLF, and the signature covers bytes.
  MANIFEST.write_bytes((json.dumps(manifest, indent=2) + "\n").encode())
  SIGNATURE.unlink(missing_ok=True)
  subprocess.run(["ssh-keygen", "-Y", "sign", "-f", key, "-n", NAMESPACE, MANIFEST], check=True)
  print(f"signed pos package version {manifest['version']}; commit pos/manifest.json and its .sig")


def main() -> None:
  """Parse arguments and run ``check`` or ``sign``."""
  parser = argparse.ArgumentParser(description="Sign or verify the POS package manifest.")
  parser.add_argument("--check", action="store_true", help="verify instead of signing")
  args = parser.parse_args()
  if args.check:
    check()
    return
  key = os.environ.get("POS_TUNNEL_SIGNING_KEY")
  if not key:
    sys.exit("set POS_TUNNEL_SIGNING_KEY to the release signing private key's path")
  sign(key)


if __name__ == "__main__":
  main()
