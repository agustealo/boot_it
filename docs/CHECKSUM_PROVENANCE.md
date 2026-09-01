# Checksum provenance

Boot It distinguishes three separate claims that are often incorrectly collapsed into one:

1. **Local digest**: Boot It calculated a SHA-256 value for the selected image.
2. **Manifest match**: that digest matches the entry bound to the image filename in a selected checksum manifest.
3. **Publisher authenticity**: the checksum manifest itself is cryptographically authenticated as coming from the intended publisher.

The current implementation proves claims 1 and 2. It does **not** yet claim 3.

## Supported SHA-256 manifest forms

Boot It accepts common SHA-256 text formats, including:

```text
<64-hex-digest>  image.iso
<64-hex-digest> *image.iso
SHA256 (image.iso) = <64-hex-digest>
```

A manifest containing only one bare 64-character SHA-256 digest is accepted only when it contains exactly one checksum entry. This avoids silently applying one anonymous checksum from a multi-entry file to the wrong image.

## Filename binding

For named entries Boot It binds the checksum to the selected image filename. It does not accept a checksum for a different filename merely because the hash text is present somewhere in the manifest.

If multiple manifest paths share the selected image basename and contain different SHA-256 values, the result is **ambiguous** and writing is blocked.

GNU escaped-filename checksum syntax is deliberately ignored rather than partially decoded. A provenance parser must not guess which filename a digest belongs to.

## Write gate

Checksum manifests are optional. If no manifest is selected, the normal structural, target-identity, capacity, and verification gates remain in force.

Once a manifest is selected, Boot It requires a successful filename-bound SHA-256 match before allowing the write. The write is blocked when the result is:

- mismatch;
- image not listed;
- ambiguous/conflicting entries;
- invalid/unparseable manifest; or
- stale because the image changed after its SHA-256 was calculated.

The manifest is re-read at the destructive boundary instead of trusting a stale earlier UI result.

## Authenticity boundary

A matching local checksum file can still be malicious if an attacker supplied both the image and the checksum file. Boot It therefore labels a successful result as a **manifest match** and explicitly reports that manifest authenticity has not been independently verified.

A future publisher-authenticity layer must verify detached signatures or another publisher-controlled trust mechanism against explicit trusted keys. It must not infer trust from a filename, download directory, TLS alone, or an arbitrary URL adjacent to the image.