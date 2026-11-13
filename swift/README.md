# Overview

This is a binding to the Signal client code in rust/, implemented on top of the C FFI produced by rust/bridge/ffi/. It's set up as a CocoaPod for integration into the Signal iOS client and as a Swift Package for local development.

## LetKnow stage CDSI (0.94.1-letknow.1)

Use the matching source tag and binary archive from the LetKnow release.
The archive supplies arm64 device and arm64/x86_64 simulator libraries.
Verify its SHA-256 checksum and compare `ios-source-revision.txt` with the source commit.
Extract the archive into the matching checkout and use a local CocoaPod:

```ruby
pod 'LibSignalClient', path: '../libsignal'
```

Run `pod install` in the app repository. Keep the CocoaPods module settings described below.
The local pod uses these libraries directly. It does not download the Signal archive.

The complete LetKnow transport is available on iOS 15 and later:

```swift
let discovery = try NitroContactDiscovery.letKnowStage()
let result = try await discovery.lookup(
    username: credentials.username,
    password: credentials.password,
    newE164s: phoneNumbers,
    accessKeys: knownAccessKeys,
    onToken: { token in
        // Save the token and this request's full phone-number set atomically.
        try await tokenStore.save(token, numbers: phoneNumbers)
    }
)
```

`credentials` come from the chat server's authenticated `GET /v2/directory/auth` endpoint.
`phoneNumbers` is `[UInt64]`, without the `+` prefix. The maximum is 1,000 numbers.
`knownAccessKeys` contains `NitroContactDiscovery.AccessKey` values with an ACI UUID and its 16-byte UAK.
`tokenStore` is application-owned storage; the sample names are integration placeholders.

The result contains each requested number, optional PNI, optional ACI, token and permit count.
An absent number has no identifiers. ACI requires a matching UAK; PNI does not.
Handle `Failure.unauthorized` by obtaining fresh credentials.
Handle `Failure.rateLimited` using its retry delay.
On `Failure.invalidToken`, clear the token and previous-number set, then make a fresh lookup.
On other failures, retain the last saved token and its number set for a retry.

For incremental lookup, pass the saved token and `previousE164s`.
Move removed numbers into `discardE164s`; put added numbers in `newE164s`.
Save the replacement token with `previousE164s + newE164s` before `onToken` returns.
A charged token lets the client reuse previous numbers without another lookup charge.
Tokens expire after 24 hours. Keep separate state for each authenticated account.

The stage endpoint is `wss://chat.stage.letknow.info:8443/v1/nitro/discovery`.
`letKnowStage()` includes the LetKnow TLS root and approved Nitro measurements.
TLS hostname checks, AWS attestation, fresh challenges and PQ Noise remain mandatory.
An enclave image update requires a matching trusted SDK policy update.
Use this API for LetKnow discovery; the original `Net.cdsiLookup` retains its SGX service path.

The **Release - iOS** workflow builds the same three architectures.
Use `dry_run: true` for a workflow artifact, or a version tag with `dry_run: false` for a release.


# Use as CocoaPod

1. Make sure you are using `use_frameworks!` in your Podfile. LibSignalClient is a Swift pod and as such cannot be compiled as a plain library.

2. Add 'LibSignalClient' as a dependency in your Podfile, as well as the prebuild checksum for the latest release. You can find the checksum in the [GitHub Releases][] for the project.

        pod 'LibSignalClient', git: 'https://github.com/signalapp/libsignal.git'
        ENV['LIBSIGNAL_FFI_PREBUILD_CHECKSUM'] = '...'

3. Use `pod install` or `pod update` to build the Rust library for all targets. You may be prompted to install Rust dependencies (`cbindgen`, `rust-src`).

4. Either disable "Swift Compiler - General - Explicitly Built Modules" (`SWIFT_ENABLE_EXPLICIT_MODULES`), or add a (non-recursive) header search path to `$(PODS_ROOT)/LibSignalClient/swift/Sources/SignalFfi`. (Sorry.)

5. Build as usual. The Rust library will automatically be linked into the built LibSignalClient.framework.

[GitHub Releases]: https://github.com/signalapp/libsignal/releases


## Development as a CocoaPod

Instead of a git-based dependency, use a path-based dependency to treat LibSignalClient as a development pod. Since [`prepare_command`s][pc] are not run for path-based dependencies, you will need to build the Rust library yourself. (Xcode should prompt you to do this if you forget.)

    CARGO_BUILD_TARGET=x86_64-apple-ios swift/build_ffi.sh --release
    CARGO_BUILD_TARGET=aarch64-apple-ios-sim swift/build_ffi.sh --release
    CARGO_BUILD_TARGET=aarch64-apple-ios swift/build_ffi.sh --release

The CocoaPod is configured to use the release build of the Rust library. Use `LIBSIGNAL_TESTING_DISABLE_EXPLICIT_MODULES=1 pod lib lint` to validate locally. You can pass `--debug-level-logs` to `build_ffi.sh` to turn on debug- and verbose-level logs.

When exposing new APIs to Swift, you will need to add the `--generate-ffi` flag to your
`build_ffi.sh` invocation.

[pc]: https://guides.cocoapods.org/syntax/podspec.html#prepare_command


## Testing a local build with Signal-iOS

The iOS Podfile has a commented-out line to use a checkout of libsignal as a path-based dependency. Uncomment that and run `pod install` (or `bundle exec pod install`, see the iOS app repo for more details). Run the build commands in "Development as a CocoaPod", and then build the iOS app from its Xcode workspace as usual. When you're done, revert the changes to the Podfile and run `pod install` again.


# Development as a Swift Package

1. Build the Rust library using `swift/build_ffi.sh`. The Swift Package.swift is configured to use the debug build of the Rust library.

2. Use `swift build` and `swift test` as usual from within the `swift/` directory.

When exposing new APIs to Swift, you will need to add the `--generate-ffi` flag to your
`build_ffi.sh` invocation. This requires installing the `cbindgen` Rust tool:

```shell
$ cargo +stable install cbindgen
```

## Use as a Swift Package

...is not supported. In theory we could make this work through the use of a custom pkg-config file and requiring clients to set `PKG_CONFIG_PATH` (or install the Rust build products), but since Signal itself does not use this configuration it's considered extra maintenance burden. Development as a package is supported as a lightweight convenience (as well as a cross-platform one), but the CocoaPods build is considered the canonical one.


# Benchmarks

The package in Benchmarks is set up for *relative* benchmarking on a build machine (rather than on iOS devices). This is mostly interesting to test that the bridging layer is not imposing undue overhead. Best results will come from testing on an Apple Silicon Mac, since that's closest in system libraries to an iOS device.

1. Build the Rust library using `swift/build_ffi.sh --release`.

2. `swift run -c release` from within the `swift/Benchmarks/` directory.

SwiftPM hides the executable in `.build/release/`, but you can find it there to run profiling tools on it.


# Catalyst Support

Mac Catalyst is not supported by this repository, but we've done experiments with it in the past. Rust targets for Catalyst are still in tier 3 support, so we use the experimental `-Zbuild-std` flag to build the standard library.

In order to compile for Catalyst you will need to:
* Install the standard library component with `rustup component add rust-src`
* Add the `--build-std` flag to your `build_ffi.sh` invocation

There may be other issues. For example, at one point the `cmake` crate had trouble compiling for Catalyst; you can try downgrading to version 0.1.48 if that's affecting you.
