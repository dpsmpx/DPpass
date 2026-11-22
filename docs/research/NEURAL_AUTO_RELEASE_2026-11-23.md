# DPpass neural AUTO signed experimental test APK (2026-11-23)

## Functionality

The current source already generates two separate on-device model files, no
GitHub download or bundled pretrained model required:

- Server selector: user picks 32, 128, 512 or 1024 hidden neurons in Settings.
  The MLP is used only for Automatically-selected provider subscription
  servers, after the existing planner filters out invalid/unhealthy options.
  Four or more real observations allow cautious adjacent re-ranking.
  Locally trained numeric weights survive reconnects, without storing
  subscription URLs, server identifiers, secrets or traffic.
- Zapret2 strategy selector: separately generated and applied to new local
  strategy connections. It does not replace the provider server model.

For field validation, `server_auto_model` logs only installation status,
hidden layer width, accumulated observations, number of candidates, and
number of changed ranks. No server names or addresses are logged.

## Signing and upgrade warning

Release identity: `com.dpsmpx.dppass`, versionCode **134**, versionName
`0.7.56-dev`. This optimized release is signed only by the pinned
GitHub Actions **alpha** certificate:

`c18792812566ca4a18b518d51313515ff2d62bf8299446e99943eeb5d0630d11`

That is different from the original development certificate
(`807cc957c376a09c9363d99ce05a1f5b9005f213ca3a1923db58b646a761e64f`)
and from the store signing certificate. Only an installed copy signed by
the identical alpha certificate with versionCode < 134 can be upgraded
in place. Never uninstall the original app merely to bypass an Android
signature mismatch: that can delete stored subscriptions and keys.

## Test on Android

1. Confirm that the currently installed `com.dpsmpx.dppass` has the
   same certificate as the signed release.
2. Keep the provider subscription and use the main-screen VPN-server
   path. Choose Automatically in Servers.
3. In Settings, generate the server model, starting at 128 neurons.
4. Make multiple real connection attempts. Look for `server_auto_model`
   with nonzero `observations` and a possible `reordered` after warm-up.
5. Repeat with 32/512/1024 sizes. Verify manually chosen profiles remain
   pinned and subscriptions persist. Test mobile and Wi-Fi separately.
6. Separately generate the strategy model only for local Zapret2 use.

CI validates build and signature; successful server choice and YouTube
playback require real-device tests, not just connectivity markers.
