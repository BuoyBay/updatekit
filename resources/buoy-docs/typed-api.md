---
title: "updatekit typed API"
summary: "Source-derived public signatures, properties, parameters, defaults, and return values."
category: "Reference"
order: 21
types: ["UpdateException", "UpdateOptions", "UpdateSession", "UpdateSnapshot", "UpdateSource"]
dependencies: []
symbols: ["UpdateException", "UpdateOptions", "UpdateSession", "UpdateSnapshot", "UpdateSource"]
related: ["api.md", "getting-started.md", "index.md"]
---

# updatekit typed API

Generated from the package source declarations. Platform guards are shown where present; inherited members are documented on the base type. See the [API contracts](api.md) for behavior and limitations.

## UpdateException

`Public Class UpdateException Inherits Exception`

### Constructor

`Public Sub Constructor(message As String)`

#### Parameters

| Name | Type | Passing | Default |
| --- | --- | --- | --- |
| `message` | `String` | `ByVal` | Required |

Returns: no value.

## UpdateSource

`Public Class UpdateSource`

### SelfHosted

`Public Shared Function SelfHosted(url As String, token As String = "") As UpdateSource`

A signed update-manifest.json served over HTTPS.

#### Parameters

| Name | Type | Passing | Default |
| --- | --- | --- | --- |
| `url` | `String` | `ByVal` | Required |
| `token` | `String` | `ByVal` | `""` |

#### Returns

| Type |
| --- |
| `UpdateSource` |

### GitHub

`Public Shared Function GitHub(owner As String, repository As String, token As String = "", apiURL As String = "https://api.github.com", manifestAsset As String = "update-manifest.json", maxReleases As Integer = 20) As UpdateSource`

Each release contains an exact named signed manifest asset. Token stays on the API origin.

#### Parameters

| Name | Type | Passing | Default |
| --- | --- | --- | --- |
| `owner` | `String` | `ByVal` | Required |
| `repository` | `String` | `ByVal` | Required |
| `token` | `String` | `ByVal` | `""` |
| `apiURL` | `String` | `ByVal` | `"https://api.github.com"` |
| `manifestAsset` | `String` | `ByVal` | `"update-manifest.json"` |
| `maxReleases` | `Integer` | `ByVal` | `20` |

#### Returns

| Type |
| --- |
| `UpdateSource` |

## UpdateOptions

`Public Class UpdateOptions`

### Properties

| Name | Type | Read-Only | Shared | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `AppID` | `String` | No | No | — | — |
| `CurrentVersion` | `String` | No | No | — | — |
| `Source` | `UpdateSource` | No | No | — | — |
| `PublicKey` | `String` | No | No | — | — |
| `Channel` | `String` | No | No | `"stable"` | — |
| `Platform` | `String` | No | No | — | — |
| `Architecture` | `String` | No | No | — | — |
| `TimeoutSeconds` | `Integer` | No | No | `120` | — |
| `MaxDownloadBytes` | `Integer` | No | No | `1073741824` | — |
| `MinimumSequence` | `Integer` | No | No | `0` | — |
| `AllowHTTPLoopback` | `Boolean` | No | No | `False` | — |

### Constructor

`Public Sub Constructor(appID As String, currentVersion As String, source As UpdateSource, publicKey As String)`

#### Parameters

| Name | Type | Passing | Default |
| --- | --- | --- | --- |
| `appID` | `String` | `ByVal` | Required |
| `currentVersion` | `String` | `ByVal` | Required |
| `source` | `UpdateSource` | `ByVal` | Required |
| `publicKey` | `String` | `ByVal` | Required |

Returns: no value.

## UpdateSnapshot

`Public Class UpdateSnapshot`

An immutable view of an operation. Obtain a fresh snapshot to see progress.

### Properties

| Name | Type | Read-Only | Shared | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `State` | `String` | Yes | No | — | — |
| `IsBusy` | `Boolean` | Yes | No | — | — |
| `ErrorMessage` | `String` | Yes | No | — | — |
| `BytesReceived` | `Integer` | Yes | No | — | — |
| `TotalBytes` | `Integer` | Yes | No | — | — |
| `Version` | `String` | Yes | No | — | — |
| `ReleaseNotes` | `String` | Yes | No | — | Plain untrusted text. Do not render it as active HTML. |
| `Sequence` | `Integer` | Yes | No | — | — |
| `DownloadPath` | `String` | Yes | No | — | — |
| `TransactionPath` | `String` | Yes | No | — | — |
| `TransactionState` | `String` | Yes | No | — | — |
| `TransactionError` | `String` | Yes | No | — | — |

### ThrowIfFailed

`Public Sub ThrowIfFailed()`

No parameters.

Returns: no value.

## UpdateSession

`Public Class UpdateSession`

Confine this object to one caller thread. Its native workers never call Buoy code. GUI apps poll from a timer; console apps can poll and Thread.Sleep between snapshots.

### Constructor

`Public Sub Constructor(options As UpdateOptions)`

#### Parameters

| Name | Type | Passing | Default |
| --- | --- | --- | --- |
| `options` | `UpdateOptions` | `ByVal` | Required |

Returns: no value.

### Check

`Public Sub Check()`

Fetch and authenticate metadata; does not download the application.

No parameters.

Returns: no value.

### LoadManifest

`Public Sub LoadManifest(envelope As String)`

Authenticate caller-supplied signed metadata without any network request.

#### Parameters

| Name | Type | Passing | Default |
| --- | --- | --- | --- |
| `envelope` | `String` | `ByVal` | Required |

Returns: no value.

### Download

`Public Sub Download()`

Stream and verify the selected asset into an owned private temporary directory.

No parameters.

Returns: no value.

### AdoptFile

`Public Sub AdoptFile(filePath As String)`

#### Parameters

| Name | Type | Passing | Default |
| --- | --- | --- | --- |
| `filePath` | `String` | `ByVal` | Required |

Returns: no value.

### VerifyFile

`Public Sub VerifyFile(filePath As String)`

#### Parameters

| Name | Type | Passing | Default |
| --- | --- | --- | --- |
| `filePath` | `String` | `ByVal` | Required |

Returns: no value.

### SaveDownload

`Public Sub SaveDownload(filePath As String)`

Copy a verified download to a new path; refuses to overwrite existing files.

#### Parameters

| Name | Type | Passing | Default |
| --- | --- | --- | --- |
| `filePath` | `String` | `ByVal` | Required |

Returns: no value.

### PrepareInstall

`Public Sub PrepareInstall(target As String, executable As String = "")`

Extract, validate and stage next to target; does not replace the installed app. executable is a relative path inside a directory target, or empty for a single binary.

#### Parameters

| Name | Type | Passing | Default |
| --- | --- | --- | --- |
| `target` | `String` | `ByVal` | Required |
| `executable` | `String` | `ByVal` | `""` |

Returns: no value.

### PrepareInstall (overload 2)

`Public Sub PrepareInstall(target As String, executable As String, arguments As Array Of String)`

#### Parameters

| Name | Type | Passing | Default |
| --- | --- | --- | --- |
| `target` | `String` | `ByVal` | Required |
| `executable` | `String` | `ByVal` | Required |
| `arguments` | `Array Of String` | `ByVal` | Required |

Returns: no value.

### InstallAfterExit

`Public Sub InstallAfterExit(relaunch As Boolean = False)`

Hand off to the bundled helper. The host must then exit itself; no forced exit occurs. Relaunch is opt-in. Use the exact helper binary built for this package and platform.

#### Parameters

| Name | Type | Passing | Default |
| --- | --- | --- | --- |
| `relaunch` | `Boolean` | `ByVal` | `False` |

Returns: no value.

### InstallAfterExit (overload 2)

`Public Sub InstallAfterExit(helperPath As String, relaunch As Boolean = False)`

#### Parameters

| Name | Type | Passing | Default |
| --- | --- | --- | --- |
| `helperPath` | `String` | `ByVal` | Required |
| `relaunch` | `Boolean` | `ByVal` | `False` |

Returns: no value.

### Rollback

`Public Sub Rollback(transactionPath As String)`

Explicitly restore the retained backup after a failed update or health check.

#### Parameters

| Name | Type | Passing | Default |
| --- | --- | --- | --- |
| `transactionPath` | `String` | `ByVal` | Required |

Returns: no value.

### Recover

`Public Sub Recover(target As String)`

#### Parameters

| Name | Type | Passing | Default |
| --- | --- | --- | --- |
| `target` | `String` | `ByVal` | Required |

Returns: no value.

### InspectTransaction

`Public Sub InspectTransaction(transactionPath As String)`

#### Parameters

| Name | Type | Passing | Default |
| --- | --- | --- | --- |
| `transactionPath` | `String` | `ByVal` | Required |

Returns: no value.

### RelaunchedTransactionPath

`Public Shared Function RelaunchedTransactionPath() As String`

No parameters.

#### Returns

| Type |
| --- |
| `String` |

### ConfirmHealthy

`Public Sub ConfirmHealthy(transactionPath As String)`

#### Parameters

| Name | Type | Passing | Default |
| --- | --- | --- | --- |
| `transactionPath` | `String` | `ByVal` | Required |

Returns: no value.

### Snapshot

`Public Function Snapshot() As UpdateSnapshot`

No parameters.

#### Returns

| Type |
| --- |
| `UpdateSnapshot` |

### WaitUntilIdle

`Public Function WaitUntilIdle(timeoutMilliseconds As Integer = 0) As UpdateSnapshot`

#### Parameters

| Name | Type | Passing | Default |
| --- | --- | --- | --- |
| `timeoutMilliseconds` | `Integer` | `ByVal` | `0` |

#### Returns

| Type |
| --- |
| `UpdateSnapshot` |

### Cancel

`Public Sub Cancel()`

No parameters.

Returns: no value.

### Close

`Public Sub Close()`

Cancels work and releases this handle. A handed-off installer remains independent.

No parameters.

Returns: no value.

### Destructor

`Public Sub Destructor()`

No parameters.

Returns: no value.
