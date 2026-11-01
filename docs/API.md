# UpdateKit

A reusable, headless updater for Buoy GUI and console apps on macOS, Windows and
Linux, on arm64 and x86_64. Consumers write `Import updatekit`. Construction and
import do not access the network, prompt, exit, or launch another process.

UpdateKit follows Sparkle's useful separation between finding an update and
installing it. It uses its own signed JSON protocol; it does not consume Sparkle
XML appcasts. Self-hosted servers and GitHub Releases publish the same manifest.
The native implementation is Rust with rustls HTTPS, Ed25519, streaming SHA-256,
and ZIP/tar support. End-user applications require neither Python nor a Rust
installation. Build and publishing tools use Python; release signing uses OpenSSL.

## Host integration

See the compilable [console example](../examples/updatekit_console.bui) and
[timer-driven GUI example](../examples/updatekit_gui.bui).
Create an `UpdateSource` using `SelfHosted` or `GitHub`, an `UpdateOptions` with
your application identifier, current SemVer, source and pinned public key, then an
`UpdateSession`. Options are copied when the session is constructed.

| Action | Result when successful | Side effects |
| --- | --- | --- |
| `Check()` | `available` or `current` | Fetches and authenticates metadata only |
| `LoadManifest(envelope)` | `available` or `current` | Authenticates supplied metadata offline |
| `Download()` | `downloaded` | Streams selected bytes into a private temporary directory and verifies them |
| `AdoptFile(filePath)` | `downloaded` | Verifies and copies a local file into private staging for offline installation |
| `VerifyFile(filePath)` | `verified` | Checks a caller's file against the selected signed descriptor |
| `SaveDownload(filePath)` | `saved` | Copies a verified download to a new caller-owned file; refuses overwrite |
| `PrepareInstall(target, executable, arguments)` | `prepared` | Creates a persistent staged transaction beside the target; leaves the target running |
| `InstallAfterExit(relaunch)` | `handed_off` | Starts the bundled independent helper; the host must then exit itself |
| `InspectTransaction(transactionPath)` | `inspected` | Reads helper state and its last error without modifying the installation |
| `Recover(target)` | `recovered` | Restores an interrupted swap, including one with a currently missing target |
| `Rollback(transactionPath)` | `rolled_back` | Restores the retained backup; also handles interrupted replacement |
| `ConfirmHealthy(transactionPath)` | `confirmed` | Commits a healthy installation and removes its backup |

Every action starts native worker work and returns promptly. Call `Snapshot()`
from the same caller thread until `IsBusy` is false. GUI apps use a timer and
update their controls on the main thread. Console apps can sleep between polls,
as the example does. No GUI run loop or Buoy callback is required. There is one
active action per session. Console callers can use `WaitUntilIdle()` instead of polling; its optional wait timeout leaves the action running. `ThrowIfFailed()` surfaces an operation failure;
`cancelled` is a separate terminal state. Snapshots are immutable views, so obtain
a fresh one for progress. `BytesReceived`, `TotalBytes`, `Version`, `ReleaseNotes`,
`Sequence` (also reported when current), `DownloadPath` and `TransactionPath` expose the relevant results.

`Cancel()` is cooperative. A blocked network read can take up to the configured
request timeout to return. Closing a session cancels work without joining its
worker on the GUI thread; worker-owned temporary data is released when it stops.
A handed-off installer has an independent lifetime. Keep a session open while
using its temporary download; call `SaveDownload` to retain bytes independently.

All application-level choices stay with the host: consent, update UI, periodic
checks, release-note presentation, when to quit, relaunch, and health policy.
For check-only use, stop after `Check`. For download-only use, save the download
and stop. Installation does not require relaunch: its default is false.

## Sources and trust

`SelfHosted(url, token)` accepts an HTTPS manifest URL. `GitHub(owner, repository,
token, apiURL, manifestAsset, maxReleases)` defaults to `https://api.github.com` and the exact
asset name `update-manifest.json`. GitHub Enterprise can supply an API root such
as `https://github.example/api/v3`. Tokens are optional bearer credentials and
remain on the configured source origin. They are stripped on redirects to another
origin and are never restored later in that redirect chain.

GitHub discovery examines a configurable window of recent releases (20 by
default, `maxReleases` in 1–10,000), paginating when needed. It selects the highest
eligible signed SemVer at the newest applicable signed sequence within that
window. This bounds ordinary public API usage; increase the window with an API
token when older target-specific releases must remain discoverable. It does not
infer compatibility from filenames. Drafts are ignored;
the signed channel determines eligibility. Historical manifests are authenticated
before expired or below-floor publications are skipped. Invalid signatures fail
the check. Use public HTTPS asset URLs for public releases and the API asset URL
for private release downloads. A manifest may map all six target combinations.

`Platform` is `macos`, `windows`, or `linux`; `Architecture` is `arm64` or `x86_64`.
Both default to the compiler target and can be overridden for a check/download
client. Installation must match the running host. `Channel` defaults to `stable`,
which excludes SemVer prereleases. Other channels match exactly. Version build
metadata does not affect precedence; equal and older versions are not updates.
`current` means no compatible newer release was found, including when a newer
release has no asset for this target.

Every manifest requires an Ed25519 signature verified with the application's
pinned 32-byte public key (64 hex characters). The signature authenticates the
exact payload bytes before parsing; the signed payload binds application ID,
version, channel, platform, architecture, artifact URL, length and SHA-256.
A checksum supplied by the hosting service alone does not establish publisher
identity. TLS verification cannot be disabled. Redirects are bounded, reject
HTTPS downgrade, and never invoke a shell.

Manifests expire at a Unix timestamp. `MinimumSequence` lets the host enforce a
persisted anti-replay floor. Persist the highest accepted sequence in the host's
own settings and pass it into subsequent sessions; the updater does not write
application preferences automatically. The current-version check also blocks
ordinary downgrades. Sequence persistence and a reliable local clock are needed
for stronger replay/freeze protection. A single pinned key is supported; rotate
it by shipping a release signed by the old key that embeds the new key before
moving publication to the new key. Keep a recovery distribution channel.

The manifest and JSON parser reject duplicate keys and unknown schema fields.
Metadata is bounded to 4 MiB per response and discovery to 64 MiB/100 pages;
asset bytes are streamed with an actual-byte limit and exact length/hash checks.
The default asset limit is 1 GiB and request timeout is 120 seconds (1–3600).
`AllowHTTPLoopback` permits numeric loopback HTTP only for tests. Release notes are
untrusted plain text; UpdateKit never renders HTML or opens their links.

## Publishing

Create an offline Ed25519 keypair once. The private PEM is written with owner-only
permissions on POSIX, and neither command below overwrites an existing file.

```sh
python3 tools/updatekit_release.py keygen \
  --private-key /secure/location/update-private.pem \
  --public-key update-public.hex
```

Pin the public hex in your app. Package each complete portable application tree
in a ZIP or gzip tar archive. `entry` is the exact relative directory inside the
archive to install. For a genuinely standalone executable, use `binary` and an
empty entry. Most Buoy apps have native libraries and Resources and should ship
as a whole tree.

```sh
python3 tools/updatekit_release.py manifest \
  --private-key /secure/location/update-private.pem \
  --output update-manifest.json \
  --app-id com.example.myapp --version 1.2.0 --sequence 12 \
  --asset linux x86_64 tar.gz MyApp MyApp-linux-x86_64.tar.gz \
    https://downloads.example.com/1.2.0/MyApp-linux-x86_64.tar.gz \
  --asset macos arm64 zip MyApp.app MyApp-macos-arm64.zip \
    https://downloads.example.com/1.2.0/MyApp-macos-arm64.zip
```

Repeat `--asset` for other targets. The tool hashes the actual artifact and signs
payload bytes through OpenSSL's Ed25519 implementation. Expiry defaults to 30
days; `--expires` accepts Unix seconds. `--notes-file` supplies plain text. Keep
keys outside the repository and your public hosting directory. Publish assets
first, then the manifest. For GitHub, attach it with the configured exact asset
name to the release, alongside the mapped artifacts.

The outer JSON has `payload` (standard base64 of UTF-8 JSON) and `signature`
(128-character signature hex). The payload schema is:

```json
{
  "schema": 1,
  "app_id": "com.example.myapp",
  "sequence": 12,
  "expires": 2000000000,
  "releases": [{
    "version": "1.2.0",
    "channel": "stable",
    "notes": "Release notes",
    "assets": [{
      "platform": "linux",
      "arch": "x86_64",
      "url": "https://downloads.example.com/MyApp.tar.gz",
      "size": 123456,
      "sha256": "64 hex characters",
      "format": "tar.gz",
      "entry": "MyApp"
    }]
  }]
}
```

`expires` and `sequence` must fit the exact JSON integer range (0 through 2^53−1).
Do not reserialize the decoded payload before verifying its signature. Release
artifacts themselves are hashed again before installation, including in the helper.

## Installation scope

Built-in installation targets portable, existing, user-writable installations:
a single executable, a full Windows/Linux app directory, or a macOS `.app`.
Provide the absolute target path. For directory installs, supply the relative
executable to relaunch (for example `MyApp.exe` or `Contents/MacOS/MyApp`) and an
array of arguments. These launch values come from the host, never the feed.
`PrepareInstall` stages beside the target so final renames stay on one filesystem.
The archive must contain the exact `entry` directory (or leave entry empty to
install the archive root). Extraction rejects traversal, case collisions, device
files, hard links and escaping symlinks; safe framework symlinks are created last
on Unix. Windows archives must not contain symlinks. Expansion is capped at 8 GiB
and 100,000 members, including members outside the selected entry. GNU long names
and bounded PAX path metadata are supported; sparse files, global PAX path/size
overrides and PAX sizes differing from the member header are rejected.
Setuid/setgid/sticky and group/other write bits are removed. Native files and
folders are flushed before replacement on Unix; Windows uses journaled ordered
renames but does not provide Unix-style directory fsync or write-through renames.
Transactions and journals require current-user ownership and private permissions;
Windows transaction ACLs grant the user and SYSTEM access; ownership by the
user, Administrators or SYSTEM is accepted, including files created by an already
elevated host. This never requests elevation. Unix installation
paths must be protected from other users' writes, either by a private ancestor or
by safe parent permissions. Lock files remain beside the target after cleanup.

The helper is copied outside the installation being replaced, waits for the
original process to exit, validates the staged artifact again, and replaces the
installation under a per-target lock. No app is forcibly terminated. A retained
backup and durable journal allow explicit rollback and health confirmation.
Directory replacement uses ordered renames with recovery; two renames are not a
single atomic filesystem operation. Preserve `TransactionPath` before exiting
so the new process can confirm success or the host can offer recovery.
When relaunch is enabled, `UpdateSession.RelaunchedTransactionPath()` also returns
the `BUOY_UPDATE_TRANSACTION` value supplied by the helper. Run the application's
own health checks before calling `ConfirmHealthy`. `InspectTransaction` reports
`TransactionState` and `TransactionError` for startup diagnostics. On Windows,
rollback from a running new executable can fail because it is mapped; exit it
first and invoke the helper's `rollback <transaction>` maintenance command.

Successful handoff means the helper accepted the transaction, not that replacement
or application startup has already succeeded. The host exits only after seeing
`handed_off`. The journal records installation results. A helper timeout or failed
replacement must be surfaced by the application's recovery workflow.

There is no privilege escalation, silent system-installer execution, background
service, delta patching, resumable download, package-manager overwrite policy, or
automatic scheduling. Use download/verification with a host-controlled installer
adapter for MSI/PKG/DEB/RPM and managed installations. Sandboxed and store apps
must use their distribution platform's update mechanism. Windows Authenticode
and release notarization remain publisher responsibilities in addition to the
cross-platform Ed25519 trust check. Test each product's signed layout on its OS.

## Build and verification

Build with Rust 1.93+, Python 3.11+, and the Buoy toolchain:

```sh
python3 tools/build_updatekit.py
```

The native CI matrix (not included in this repository) runs Rust tests and builds on all six native runner architectures. Runner labels follow the [GitHub runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

The builder uses Cargo.lock, builds the library and independent helper, checks the
Buoy module on all six targets and seals `packages/updatekit-0.1.0.buipkg` (also
copied to `dist`). It includes dependency license notices. Native source receipts
prevent stale slices entering a newly sealed package. Build on each target OS
with `--target`, or supply a working Rust cross toolchain. `--native-only` builds
a slice; `--seal-only` combines existing current slices. Windows import libraries
are included. The initial package may contain only locally built slices; the
presence of source code for six targets does not imply all native binaries ship.

A combined package carries every included target helper as a resource; a product can seal a single-target slice to keep its distribution small.

The helper ships as a package resource under `<target>/buoy-update-helper[.exe]`.
`InstallAfterExit()` resolves it automatically. An overload accepts an explicit
helper path for custom application layouts. Copy resources before final app
signing. On macOS, `BUOY_CODESIGN_IDENTITY` signs the built native library and
helper before sealing; sign/notarize the enclosing app as part of product release.
Do not substitute an arbitrary downloaded helper or sign the app before embedding
its updater resources. Dependency notices are in `Resources/updatekit/third-party`.

Tests use temporary applications and loopback servers. They never replace the
running development tool or contact a production update service. Compiler checks
validate Buoy syntax on all targets. Native Linux execution verifies transport, signatures, archive safety, the
sealed Buoy consumer, helper parent exit, exact relaunch arguments, whole-folder
replacement, rollback and health confirmation. The native CI matrix builds the
helper before tests, including a Windows running-image/relaunch fixture. Windows
sources are also checked with a GNU cross toolchain and executed on the Windows
guest. See the precise remaining release checks below; the CI matrix itself was
not dispatched during this validation.

Current native validation and artifact provenance are recorded in
[PROVENANCE.md](../PROVENANCE.md) and
the machine-readable evidence.
The combined package contains current, runtime-tested **Linux x86_64, macOS
arm64, and Windows x86_64** slices. Linux and Mac run 35 library tests plus 2
helper tests; Windows runs 29 library tests plus 2 helper tests. Seven publishing
and Mach-O normalization regressions pass. The signed-feed ABI suite exercises
binary, ZIP, and tar.gz downloads, prepare without replacement, parent exit,
exact relaunch arguments, directory replacement, rollback, and confirmation.
Mac also runs an isolated sealed Buoy consumer and compiles the GUI example;
Windows runs an isolated Buoy consumer on the guest. No desktop interaction is
needed for these lifecycle tests.

Windows binaries were built with Rust's GNU target on Linux and executed on the
Windows 11 x86_64 guest. Their C ABI and COFF import library work with Buoy's
Windows consumer. The default native builder still targets MSVC. To reproduce
the validated cross build with an installed MinGW/Rust toolchain:

```sh
python3 tools/build_updatekit.py --target x86_64-windows \
  --rust-target x86_64-pc-windows-gnu --native-only
```

`--native-only` on the **test runner** skips Cargo/compiler work and accepts
explicit `--library`, `--helper`, and optional prebuilt `--payload`/`--consumer`
paths. OpenSSL is the default fixture signer. A private testing Python can use
`--signing-backend cryptography` when OpenSSL is unavailable; this dependency is
only for validation, never for end-user applications. See the recorded commands
and dependency hashes in the evidence directory.

Remaining native gaps are explicit: macOS x86_64 (no Intel execution/Rosetta),
Linux arm64 and Windows arm64 (no authorized native hosts), a native MSVC-producer
build, Developer ID bundle replacement/notarization/Gatekeeper (no signing
identity on the Mac), Windows Authenticode and kill-on-close job policy. Ad-hoc
bundle rejection is tested. These gaps are not reported as passing.

The builder now smoke-loads a host-native library before issuing its receipt.
On the observed macOS 27 linker output, it aligns the Mach-O string pool using
only verified unused LINKEDIT padding, then signs the changed library again.
It refuses unsafe layouts. Receipts bind the Rust sources **and the builder**;
CRLF is normalized when hashing for cross-host assembly.

CI uploads a native-slice artifact per runner. Merge runtime/link/resources
artifacts from the same source fingerprint, then run `--seal-only`. Use the
receipt-aware builder rather than directly sealing the source directory: stale
slices must not enter a combined package. Native Windows Buoy 0.72 package
inflation requires the stored-ZIP workaround tracked by BUI-008. Precreate output
directories before compiling; BUI-701 records the otherwise missing DLL staging.



Protocol background: [Sparkle security](https://sparkle-project.org/documentation/) and [GitHub Releases API](https://docs.github.com/en/rest/releases/releases). UpdateKit implements its own signed protocol and does not wrap either project.

Test suites and fixtures are maintainer-local and are not part of this public repository.
