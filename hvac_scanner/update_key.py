"""Public half of the release-signing key (packaging/signing.py new-key).

The updater installs only releases whose latest.json is signed by the
matching private key, which lives on the maintainer's PC, never in the
repository.
"""

UPDATE_PUBLIC_KEY = "Y5xH7OBix9zVX+Xz1LShuvy6RMK0c1QonNrJbRv97l8="
