---
title: "UpdateKit getting started"
summary: "Install and use UpdateKit with explicit configuration and resource ownership."
category: "Guides"
order: 10
keywords: ["updates", "ed25519", "github", "portable", "rollback"]
related: ["index.md", "api.md", "typed-api.md"]
---

# UpdateKit getting started

Copy the updatekit archive with its native runtime/helper resources into packages. Pin the publisher's real 64-character public-key hex in application configuration. The example obtains it from an environment variable and performs a check only; it never downloads, installs, quits, or relaunches. Replace the illustrative feed/app identity before running.

```buoy
Import updatekit

Sub Main()
    Dim publicKey As String = System.EnvironmentVariable("APP_UPDATE_PUBLIC_KEY").Or("")
    If publicKey = "" Then
        Print "Configure the pinned publisher public key first"
        Return
    End If
    Dim source As UpdateSource = UpdateSource.SelfHosted("https://updates.example/update-manifest.json")
    Dim options As New UpdateOptions("com.example.app", "1.0.0", source, publicKey)
    Dim session As New UpdateSession(options)
    Try
        session.Check()
        Dim state As UpdateSnapshot = session.WaitUntilIdle()
        state.ThrowIfFailed()
        Print state.State
    Finally
        session.Close()
    End Try
End Sub
```

## GUI integration

Check and other actions return promptly and start native worker work. In a GUI, poll Snapshot from a timer on the same caller thread until IsBusy is False instead of blocking with WaitUntilIdle. Obtain a fresh immutable snapshot for progress. One action runs per session. Closing cooperatively cancels work without joining on the UI thread.

## Optional installation workflow

Download or AdoptFile verifies the selected artifact. SaveDownload retains a copy beyond the session lifetime. PrepareInstall stages a durable transaction beside the target without stopping it. InstallAfterExit hands off to the bundled helper; after handed_off, the host chooses when to exit. Successful handoff is not proof that replacement or relaunch succeeded.

Persist TransactionPath before exit. ConfirmHealthy commits a healthy installation; Recover/InspectTransaction and Rollback support explicit recovery. Persist the highest accepted Sequence in host settings and pass MinimumSequence on later checks to strengthen replay protection.

## Read next

- [Overview](index.md)
- [Getting started](getting-started.md)
- [API reference](api.md)
