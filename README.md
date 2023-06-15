# About

[![Go Reference](https://pkg.go.dev/badge/github.com/korylprince/dep-webview-oidc.svg)](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc)

dep-webview-oidc is a Go library and server for authenticating and authorizing Apple's [Automated Device Enrollment (ADE)](https://support.apple.com/en-us/HT204142) MDM enrollment process using OpenID Connect.

# Documentation

* [Quickstart Guide](https://github.com/korylprince/dep-webview-oidc/tree/master/docs/Quickstart.md)
* [Architecture Guide](https://github.com/korylprince/dep-webview-oidc/tree/master/docs/Architecture.md)

# Features

* Works with any OpenID Connect Provider
* No persistent storage needed
  * Provide your own [storage implementation](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/store#StateStore) to horizontally scale
* Parses the `x-apple-aspen-deviceinfo` header and verifies the signature
* Includes support for MicroMDM's dynamic SCEP challenges
* Highly configurable Go library with interfaces to easily build your own authorization server
