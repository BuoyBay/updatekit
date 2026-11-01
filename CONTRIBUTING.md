# Contributing to updatekit

This repository owns the `updatekit` package at the repository root, with its
package-specific examples and metadata. Read the [source guide](docs/API.md).
Keep the compiler identity/version in `manifest.json`, BPM dependencies in
`bpm.json`, API documentation and retained upstream notices consistent.

## Development conventions

Use the installed Buoy language reference and verify changed `.bui` files with
the compiler. Prefer native Buoy/BuoyScript for new automation. Preserve public
command names, environment-variable contracts and explicit platform limitations.

## Build context

Shared build tooling and sibling package sources live in separate repositories.
Use the BuoyBay `workspace-tools` layout with this checkout at `repos/updatekit`; assemble
from that workspace root before running builders in `local/integration/`:

```sh
./dist/workspace-manager/buoybay assemble
```

Edit this owning checkout, then reassemble; the generated integration tree is
not the place to keep edits. Do not reassemble while another build is running.

Use the platform-specific build/staging instructions in the source guide for
`updatekit`. Provision its native/runtime or toolchain dependencies explicitly;
copying an existing archive or sealing sources alone does not rebuild them.

## Verification and pull requests

For each edited Buoy entrypoint, in its documented staged dependency context:

```sh
buoy path/to/entrypoint.bui --check --diagnostic-format json
```

Require exit status zero and an empty `errors` array. Read warnings. Check each
affected conditional platform branch with `--target`; compiler checks do not prove
native runtime behavior on another OS. Build/link and exercise the changed API or
workflow on its supported host as well.

Test suites, fixtures and detailed reports are private/ignored for now. Maintainers
run those suites before merge or publication; a fresh checkout is not expected to
contain them. Include your compiler/tool versions, host/target, exact build and
reproduction commands, expected behavior and observed output in the pull request.
Do not commit private tests, generated builds, caches, credentials or machine
configuration. Keep the patch focused and note any unverified platforms or runtime
prerequisites. Inventory checks alone are not build or test acceptance.

## License of contributions

Original contributions are accepted under the existing license for the files you
change: `MIT OR Apache-2.0` for first-party code and `CC-BY-4.0` for documentation
prose. Code samples follow their code's license. No CLA or DCO signing step is
required. Keep your own authorship and copyright attribution.

Read [LICENSE](LICENSE) and [LICENSING.md](LICENSING.md). Preserve upstream license,
copyright, attribution and provenance files for third-party material, and identify
its source in the pull request. Submit only material you have the right to license.
Reusable packages and tools keep their permissive licensing boundary; changes to
Studio's AGPL application code belong in its separate repository.
