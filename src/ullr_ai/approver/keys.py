"""Approver key files.

The private key never leaves the approver's side. Only the public key goes
into the Gateway's registry.
"""

import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ullr_ai.gateway import signing


def generate(private_key_path: Path | str) -> str:
    """Create a new key pair. Writes the private key (mode 0600), returns the public key.

    Refuses to overwrite an existing file.
    """
    private, public = signing.generate_keypair()
    descriptor = os.open(private_key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(private + "\n")
    return public


def load(private_key_path: Path | str) -> Ed25519PrivateKey:
    return signing.load_private_key(Path(private_key_path).read_text(encoding="ascii").strip())
