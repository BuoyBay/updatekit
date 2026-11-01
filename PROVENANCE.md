# Native platform validation

The 2026-11-01 follow-through used the current shared checkout based on
`6b7b8685`, isolated build directories, and disposable fixture applications.
No user's installed application, screen lock, permission grant, SDK or console
configuration was changed. No CI dispatch, issue publication or commit occurred.

| Slice | Build and native execution | Scope |
| --- | --- | --- |
| Linux x86_64 | Rust 1.93.1, local Linux | 35 library + 2 helper tests; isolated sealed Buoy consumer; GUI compilation; signed-feed binary/ZIP/tar.gz lifecycle and full directories |
| macOS arm64 | Rust 1.95.0, macOS 27.0.1 arm64 over coordinated SSH | 35 library + 2 helper tests; isolated sealed Buoy consumer and GUI compilation; signed lifecycle and directories; three repeated post-fix lifecycle runs; ad-hoc bundle rejection |
| Windows x86_64 | Rust 1.93.1 GNU cross build; native Windows 11 AMD64 execution over existing SSH | 29 library + 2 helper tests; running-image wait/relaunch; signed lifecycle and full directories; native Buoy consumer, with existing compiler workarounds as recorded |

Source fingerprints, runtime/helper hashes, architectures, commands, outcomes,
initial failures and successful controls are in
[updatekit_native_validation.json](../../tests/updatekit_native_validation.json)
and [the raw logs](../../tests/updatekit_native_evidence/).

## Defects fixed during native testing

- Windows `FlushFileBuffers` needs a writable file handle. Stage-tree flushing
  now opens files for writing on Windows, instead of relying on Unix's read-only
  `fsync` behavior. The original five native failures and successful retest are
  preserved.
- A Windows path test used `PathBuf::join`, which normalized its `..` input before
  validation. The fixture now passes the original spelling, and explicit Windows
  raw parent-segment validation protects verbatim paths too.
- macOS 27 dyld rejected a Rust-built dylib with a string-table offset aligned
  to four rather than eight bytes. The original Cargo output and packaged copy
  had identical hashes, excluding package-copy corruption. The builder moves
  only the string pool into checked existing padding, updates `LC_SYMTAB`, signs
  the changed dylib, and actually loads its C ABI. Synthetic regression tests
  prove symbol/signature regions stay in place and unsafe padding is rejected.
  This concerns the native bridge's linker output, not Buoy compiler lowering.
- macOS process-identity inspection occasionally failed during parent exit. A
  journal captured that exact reason. The helper now retries uncertain reads for
  at most two seconds, never equates an error with exit, and still fails closed
  for persistent denial. Deterministic tests and three native repeated suites
  cover the transition.
- The Windows HTTP unit fixture explicitly restores blocking mode on accepted
  sockets, because Winsock can inherit the nonblocking listener mode. The
  original transient `WouldBlock` failure and successful native retest are retained.
- Native test fixtures use portable C stdio, preserve Mach-O signatures, compare
  executable identity with `samefile`, use a writable report-flush handle, and
  inspect Windows PIDs without `os.kill`.

The separate Buoy output-directory staging problem was independently reproduced
and challenged as [BUI-701](../../upstream-issues/BUI-701-cross-target-output-directory/issue.json).
The local workaround is to create the output directory before compilation. The
record is validated locally and has not been published.

## Remaining gaps

No native execution was available for macOS x86_64, Windows arm64 or Linux arm64.
The Mac has neither Rosetta nor a valid signing identity, so Intel execution and
positive Developer ID bundle updates/notarization/Gatekeeper remain unverified.
The ad-hoc refusal test leaves the fixture unchanged. Windows native MSVC
production and Authenticode/job-policy qualification remain separate from the
validated GNU-produced C ABI. No unvalidated architecture is included in the
combined package.

Fixture signing on Windows used cryptography 46.0.3, cffi 2.0.0 and pycparser
2.23 in an isolated copy of embeddable Python. Download hashes are recorded;
these Python dependencies are not included in UpdateKit runtimes.
