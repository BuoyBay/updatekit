# Native runtime integration

UpdateKit combines a Rust native library with an independent installation helper.
Native source is retained under `native/`; `Cargo.lock` pins Rust dependencies.
Dependency license notices remain in `resources/third-party`.

The combined package carries Linux x86_64, macOS arm64 and Windows x86_64
runtime/helper slices. The Windows GNU-produced C ABI and COFF import library
support Buoy consumers. Native MSVC production remains a separate target.

On Windows, stage-tree flushing uses writable handles for `FlushFileBuffers`.
The helper validates the original spelling of paths before path normalization
and waits for the intended parent executable identity before replacement.
Uncertain process-identity reads are retried briefly and fail closed.

On macOS, the builder validates Mach-O string-table alignment, changes only
verified unused LINKEDIT padding when normalization is needed, then signs and
loads the changed library. Application resources must be embedded before final
signing and notarization.

Native execution for macOS x86_64, Linux arm64 and Windows arm64 remains
unverified. Developer ID bundle replacement, notarization/Gatekeeper and Windows
Authenticode/job-policy qualification require their respective production setup.
Cross-compilation alone does not establish those behaviors.
