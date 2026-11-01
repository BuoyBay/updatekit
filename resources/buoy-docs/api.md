---
title: "UpdateKit API"
summary: "Public types, operations, error behavior, and limits for UpdateKit."
category: "Reference"
order: 20
keywords: ["updates", "ed25519", "github", "portable", "rollback"]
symbols: ["UpdateSource", "UpdateOptions", "UpdateSession", "UpdateSnapshot", "UpdateException", "UpdateSource.SelfHosted", "UpdateSource.GitHub", "UpdateSession.Check", "UpdateSession.PrepareInstall", "UpdateSession.Recover"]
related: ["index.md", "getting-started.md", "typed-api.md"]
---

# UpdateKit API

| API | Contract |
| --- | --- |
| UpdateSource.SelfHosted, UpdateSource.GitHub | Signed HTTPS feed or release discovery; optional token and configurable Enterprise root/manifest asset. |
| UpdateOptions | AppID, CurrentVersion, Source, PublicKey, Channel, Platform, Architecture, TimeoutSeconds, MaxDownloadBytes, MinimumSequence, AllowHTTPLoopback. |
| UpdateSession(options) | Copies options and owns native worker state; one active action at a time. |
| Check, LoadManifest | Authenticate remote or supplied metadata; terminal available/current. |
| Download, AdoptFile, VerifyFile, SaveDownload | Obtain/verify selected bytes or retain a new caller-owned copy. |
| PrepareInstall(target, executable, arguments) | Stage beside an existing portable target; launch values are host-owned. |
| InstallAfterExit(relaunch) | Hand off to bundled helper; relaunch defaults False, host exits itself. |
| Recover, InspectTransaction, Rollback, ConfirmHealthy | Explicit durable transaction inspection/recovery, backup restore, and commit. |
| Snapshot, WaitUntilIdle, Cancel, Close | Observe, optionally block in console apps, cooperatively cancel, and release. |
| UpdateSnapshot | State, IsBusy, ErrorMessage, BytesReceived, TotalBytes, Version, ReleaseNotes, Sequence, DownloadPath, TransactionPath, TransactionState, TransactionError. |
| UpdateSnapshot.ThrowIfFailed, UpdateException | Surface failed actions; cancelled is a separate terminal state. |

## Selection and lifetime

Stable excludes SemVer prereleases; other channel names match exactly. Build metadata does not affect precedence. current can mean a newer release lacks an asset for this target. Platform/Architecture can select check/download targets, but installation must match the running host.

WaitUntilIdle timeout leaves the operation running. Cancel can wait for a bounded network read to return. Keep the session open while using temporary DownloadPath data; SaveDownload creates an independent retained file and refuses overwrite. Signed manifests expire and have a sequence floor; host-persisted sequence and a reliable clock are required for stronger replay/freeze protection.

## Read next

- [Overview](index.md)
- [Getting started](getting-started.md)
- [API reference](api.md)


[Full typed API: properties, parameters, defaults, and returns](typed-api.md)
