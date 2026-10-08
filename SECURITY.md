# Security Policy

## Reporting a vulnerability

If you find a way to make `blrecover` write to the wrong sectors, bypass one of
its safety gates, or corrupt a partition table, please report it privately via
GitHub's **Security → Report a vulnerability** tab on this repository rather
than opening a public issue. Please include the disk image or a hex dump that
reproduces it.

## Threat model

`blrecover` is designed to run as Administrator with raw
`\\.\PhysicalDriveN` access. It is not hardened against a hostile local
administrator, and it is not a security boundary. Its controls exist to stop
*accidental* damage, not deliberate ones.

Specifically:

- **It is not an isolation mechanism.** Every safety gate is an in-process
  check. Anyone who can run it elevated can drive it directly.
- **It does not decrypt anything and never reads key material.** The tool only
  parses cleartext on-disk metadata (`-FVE-FS-` volume headers, FVE metadata
  blocks, GPT/MBR structures). It never handles a BitLocker password, recovery
  key or Volume Master Key.
- **Recovering a partition entry is not a decryption bypass.** Once the entry is
  restored, Windows mounts the volume *locked*. Your own unlock credential is
  still required, and nothing in this tool can produce one.
- **Backups contain real partition-table bytes** and are written unencrypted to
  `--backup-dir` (default `blrecover-backups/`). Treat that directory as
  sensitive and delete it once you no longer need it.

## Supported versions

This is a personal project with no release cadence. Fixes land on `main` as
they are made; there are no backports to older branches.