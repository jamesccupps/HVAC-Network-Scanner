"""Public halves of the two signing keys (packaging/signing.py).

UPDATE_PUBLIC_KEY: the updater installs only releases whose latest.json is
signed by the matching private key, which lives on the maintainer's PC,
never in the repository or a repository secret.

ADVISORY_PUBLIC_KEY: the advisory list (advisories.py) is used only when it
is signed by the matching private key, which the daily advisories workflow
holds as a repository secret. That key signs the list and nothing else: the
updater never trusts it.
"""

UPDATE_PUBLIC_KEY = "Y5xH7OBix9zVX+Xz1LShuvy6RMK0c1QonNrJbRv97l8="
ADVISORY_PUBLIC_KEY = "bIyXFlZ4wNyM50QuVb+AFxUm9zDmMMUfBtVl9b46mKA="
