---
title: "UpdateKit"
summary: "Check signed updates and explicitly download, verify, install, recover, or roll back portable apps."
category: "Overview"
order: 0
keywords: ["updates", "ed25519", "github", "portable", "rollback"]
related: ["getting-started.md", "api.md", "typed-api.md"]
---

# UpdateKit

UpdateKit is a headless asynchronous updater with its own signed JSON manifest protocol for self-hosted HTTPS and GitHub Releases. Import/construction does not access the network, prompt, quit the app, or launch a process. Host applications own consent, UI, scheduling, exit, relaunch, and health policy.

## Trust and runtime

The native implementation uses Rust, rustls HTTPS, Ed25519 signatures, and streaming SHA-256. End users need neither Rust nor Python. Ship the native slice and independent installer helper for the target. The manifest binds application, version, channel, target, asset URL, size, and hash to a pinned public key.

TLS cannot be disabled. Metadata and downloads are bounded; redirects cannot downgrade HTTPS. Tokens remain origin-scoped and are stripped on cross-origin redirects. Release notes are untrusted plain text, never rendered HTML.

## Installation scope

Built-in installation supports existing user-writable portable app trees, standalone executables, and macOS app bundles. There is no elevation, system package installer policy, background service, delta patching, resume, or automatic scheduling. Store/sandbox-managed distribution should use its own update mechanism.

## Read next

- [Overview](index.md)
- [Getting started](getting-started.md)
- [API reference](api.md)
