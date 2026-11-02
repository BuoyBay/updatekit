# Signed app updates

A reusable, headless updater for GUI and console apps on macOS, Windows and
Linux, on arm64 and x86_64. Consumers write `Import updatekit`. Construction and
import do not access the network, prompt, exit, or launch another process.

## Install

From a Buoy consumer project with BPM installed:

```sh
bpm add updatekit --git https://github.com/BuoyBay/updatekit.git --rev refs/heads/main
```basic

BPM records the resolved commit in its lockfile. Keep that lockfile with the
consumer project for reproducible installs.

## Example

```basic
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

## Build and API reference

Source is in `modules/`, with native/runtime inputs where required. Use the
[package guide](docs/API.md) for backend-specific build prerequisites, ownership
rules and supported targets. Rebuilding a native backend requires that target's
compiler and SDK; sealing an archive alone does not rebuild the backend.

## Contributing

[Contributing](CONTRIBUTING.md) · [License](LICENSE)
