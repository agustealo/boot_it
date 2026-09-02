# Trusted publisher profiles

Boot It publisher profiles are convenience metadata, not a replacement for cryptographic verification.

A profile may prefill:

- the expected OpenPGP signature format (`detached` or `cleartext`), and
- a full publisher signing-key fingerprint taken from publisher-maintained verification documentation.

A profile **never** downloads or imports a public key, checksum manifest, signature, or image. The operator must still obtain those files independently and select them locally. Boot It then verifies the supplied key contains the pinned fingerprint and requires GnuPG `VALIDSIG` to match it.

## Audited source snapshot

The current registry was reviewed on 2026-09-01 against these publisher-controlled sources:

- Ubuntu release ISO verification: `https://ubuntu.com/tutorials/how-to-verify-ubuntu`
- Ubuntu public/cloud image verification: `https://ubuntu.com/docs/public-images/public-images-how-to/verify-image-checksum/`
- Fedora current OpenPGP certificates: `https://fedoraproject.org/security/`
- Debian installation-media verification: `https://www.debian.org/CD/verify`

The registry includes separate entries when a publisher documents multiple legitimate signing keys. Boot It must not collapse multiple valid keys into one guessed fingerprint.

## Maintenance rules

1. Add or rotate a fingerprint only from publisher-controlled verification documentation or an equivalently strong publisher-controlled trust channel.
2. Never populate a profile from an unauthenticated keyserver search result alone.
3. Use full fingerprints. Short or long key IDs are identifiers, not sufficient trust anchors.
4. Keep release-scoped keys release-scoped. Fedora release keys, for example, must not be presented as universal Fedora keys.
5. Do not silently remove historical profiles while images signed by those keys remain commonly distributed. Mark them clearly as legacy instead.
6. A valid profile does not make a locally supplied public-key file trustworthy by itself. The verifier still checks that the supplied key contains the exact profile fingerprint and that the manifest signature validates under it.
7. Publisher profiles do not enable network retrieval during a write. Destructive operations remain local and deterministic.

## Current profile families

- Ubuntu release ISO signing keys documented by Ubuntu
- Ubuntu public/cloud image signing key documented by Ubuntu
- Fedora 44, Fedora 45, and current Rawhide release certificates documented by Fedora
- Debian CD signing keys and Debian Testing CD automatic signing key documented by Debian

Custom/manual mode remains available for other publishers and private images.
