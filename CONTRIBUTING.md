# Contributing

Thanks for looking at this. A few things first.

## Before you contribute

- **Never open a pull request against a live recovery.** If you are testing on a
  disk that holds data you care about, work from a full image copy instead.
- **Rehearse on a synthetic image.** `blrecover mkimage` builds a sparse
  practice disk that mimics the failure mode without touching hardware:

  ```powershell
  .\build.ps1
  .\build\bin\Release\net10.0-windows\blrecover.exe mkimage --path C:\temp\practice.img --size-mb 1024 --clean
  .\build\bin\Release\net10.0-windows\blrecover.exe selftest
  ```

## What a useful PR looks like

- **Bug fixes in the parser need a failing assertion first.** `SelfTest.cs` is
  the safety net; a new case there is the strongest evidence a change is
  correct. The suite is synthetic and runs without a disk, so it must stay that
  way.
- **Do not weaken a safety gate.** The gates in `Restorer.cs` (elevation,
  backup-and-verify, serial-token confirmation, GPT-overlap hard block, boot
  disk flag) exist because a mistake destroys data. If a gate is blocking you,
  the gate is the bug, not the caller.
- **Never add key material handling.** Parsing cleartext metadata is the whole
  design boundary. Decryption is out of scope by intent, not by omission.
- Match the surrounding style: 4-space indent, explicit types, `CultureInfo`
  passed to every format call, `_camelCase` for privates.

## Building and checking

```powershell
.\build.ps1                     # build everything, Release
.\build.ps1 -Run selftest       # build, then run the engine self-test suite
.\build.ps1 -RunUiSmokeTest     # load the real WPF window and walk the tree
.\build.ps1 -SelfContained      # single standalone GUI exe into dist\
```

`--ui-demo` is safe — it runs entirely against a synthetic image in `%TEMP%` and never opens a
physical disk.

`--ui-smoke-test` loads the real window, so it **enumerates and reads the physical disks of the
machine it runs on**. It never writes, but it is not hermetic. Don't run it somewhere the disk
list is sensitive.

## Commit messages

Describe what changed and why, in the imperative mood. If a change touches
partition-table writing or the safety gates, say so explicitly in the body.