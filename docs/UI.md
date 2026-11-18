# Native UI integration notes

This is an internal source implementation, not an accepted or releasable client.

`app/main.m` starts `MLAppDelegate` in `app/MLApp.m`. The app uses Objective-C,
UIKit, QuartzCore and CoreGraphics with iOS 6.0 / ARMv7 as its deployment target.
`resources/Info.plist` identifies it as `com.muyu.clashlegacy`.

## Navigation and design

- Four fixed tabs: 首页 / 代理 / 配置 / 日志. Settings opens from the home screen.
- Every secondary page has an explicit 44pt back control.
- A 320×480pt portrait screen uses a 44pt navigation bar, 49pt native tab bar,
  56pt rows, 44pt segmented controls, 12–16pt margins and scrollable content.
- Purple tokens are `#A99AC8` / `#70558F`, background `#F7F7F9`, white surfaces,
  primary text `#25232A`. Native bar and segmented backgrounds are replaced
  with flat images; no blur, web view, continuous animation or external fonts.
- The currently integrated interface language is Simplified Chinese and the
  integrated theme is light. Other localizations/themes are not claimed.

## Data and actions

All supervisor calls use `MLIPCRequest` off the main queue. Rendering returns
to the main queue. The IPC implementation owns its five-second timeout.
Home polls status every two seconds only while it is visible and the app is
active; concurrent requests on a screen are prevented. Unknown metrics and
node latency display as unavailable / `—`; missing coverage is never inferred.
After a status read error, any retained state is labeled as the last state.

Mutations do not preemptively change the displayed running state, active
configuration, setting, or selected node. They wait for a daemon acknowledgement
and then reread status. Daemon errors remain visible. Lists have real loading,
empty and error messages, with no fixture data.

Implemented screens include configuration import sources, local readable YAML
file selection, source editing/copying/another candidate save, compatibility
report category filters, issue details, line/column editing navigation, copying,
rechecking and previous/current issue comparisons. A boolean `unchecked: true`
is explicitly displayed as remaining unchecked content rather than a pass.
Groups and nodes provide search, ordering, selection requests and long-press
details/testing. Logs offer local filters over the fetched range and export only
when `logs.list` explicitly acknowledges `redacted: true`. Connections have a
detail screen and daemon-mediated close action. Settings, DNS and diagnostics
display daemon-provided values and capability reports.

Subscription source labels hide URL user information, paths and tokens. General
JSON details hide credential fields. Raw YAML editing and copying is explicitly
labeled as possibly containing credentials.

## Explicit limitations

- The app uses the pinned ZBar QR reader to decode camera photos and saved
  images. User confirmation precedes import. Camera and photo library
  integration still require an iOS 6 device check.
- The runtime now supports local TCP forwarding, selectors, source editing,
  connection control, node probes and DNS diagnostics. Automatic groups,
  provider scheduling, full capture and unsupported settings remain
  explicit errors or disabled states.
- YAML save creates another checked candidate rather than replacing an active
  generation. YAML export currently copies raw text; no share-sheet/file export
  or override editor is claimed.
- No target-device launch, screenshot, VoiceOver run or actual 320×480 device
  layout inspection was possible here. The source dimensions and API target
  have been checked; visual and on-device behavior remain unverified.

## Build verification

Executed successfully from this directory:

```sh
../scripts/cc-ios -fobjc-arc -fblocks -Iipc -Wall -Wextra \
  -Wno-unused-parameter -Wunguarded-availability -Werror \
  -c app/MLApp.m -o /tmp/muyu-ui-app.o
../scripts/cc-ios -fobjc-arc -fblocks -Iipc \
  -c app/main.m -o /tmp/muyu-ui-main.o
../scripts/cc-ios -fobjc-arc -fblocks -Iipc \
  -c ipc/MLIPC.m -o /tmp/muyu-ui-ipc.o
../scripts/cc-ios /tmp/muyu-ui-main.o /tmp/muyu-ui-app.o /tmp/muyu-ui-ipc.o \
  -framework UIKit -framework Foundation -framework QuartzCore \
  -framework CoreGraphics -o /tmp/MuyuClash-UI-check
plutil -lint resources/Info.plist
xcrun vtool -show-build /tmp/MuyuClash-UI-check
```

The app source compile produced no diagnostics. The linked result is a Mach-O
ARMv7 executable with `LC_VERSION_MIN_IPHONEOS 6.0`. Only system framework and
runtime dependencies are linked. Compile ARC objects first and link the objects
without passing `-fobjc-arc`: a one-step ARC link with the installed modern clang
tries to load an unavailable `libarclite_iphoneos.a`.
