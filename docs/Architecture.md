# Architecture Guide

dep-webview-oidc is library for use in building your own server, and also includes [webview-server](https://github.com/korylprince/dep-webview-oidc/tree/master/cmd/webview-server), the reference implementation server. This guide will cover the architecture of dep-webview-oidc and is supplemental to the [package documentation](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc).

## Service

In both the library and the server, the [Service](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/service#Service) is the top level manager of all of the components and HTTP endpoints. 

**Endpoints**

The Service has two HTTP endpoints that are used as part of the enrollment process:

* Authorize Endpoint: https://example.tld/v1/authorize
* Callback Endpoint: https://example.tld/v1/callback

These will be referenced throughout the rest of this guide.

#### Server Configuration:

When using webview-server, the Service and its components are configured with flags (e.g. `-enroll-profile`) and/or environment variables (e.g. `ENROLL_PROFILE`). Every flag can be used as an environment variable by removing the leading dash, replacing the rest of the dashes (`-`) with underscores (`_`), and making all letters capital. Flags have precedence over environment variables.

When using the [container](https://github.com/korylprince/dep-webview-oidc/pkgs/container/dep-webview-oidc), environment variables suffixed with `_FILE` will treat `X_FILE` like a file path and set `X` to the contents of that path. For example, if `/run/secrets/api_key` has the contents `password`, and the environment variable `API_KEY_FILE=/run/secrets/api_key` is set, webview-server will also see the environment variable `API_KEY=password`.

Run `webview-server -h` to see a list of all flags and their usage.

#### Library Configuration:

When using dep-webview-oidc as a library, the Service and its components are configured with various options that are documented in the [package documentation](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc). Most of these options map directly to flags used by webview-server.

There are several Go interfaces that can be implemented to provide additional functionality not found in webview-server, which will be explored below.

# Enrollment Process

To cover the architecture, we'll go through the Automated Device Enrollment (ADE) process from start to installation of the enrollment profile, pointing out the configuration options and Go interfaces involved along the way.

## Configure DEP Profile

To configure a device to authenticate with dep-webview-oidc, it must have a [Device Enrollment Program (DEP) profile](https://developer.apple.com/documentation/devicemanagement/profile?language=objc) assigned with the `configuration_web_url` key set to dep-webview-oidc's Authorize Endpoint. Assigning a DEP profile is outside of the scope of dep-webview-oidc; [NanoDEP](https://github.com/micromdm/nanodep) is an open source option for managing DEP profiles and assignments.

## Authorize Endpoint

When a device starts the MDM enrollment process, whether through Setup Assistant or manually triggered (e.g. `sudo profiles renew -type enrollment`), it will download it's DEP profile from Apple. If the `configuration_web_url` key is set, a webview will be opened to the configured URL. In our case, it will open dep-webview-oidc's Authorize Endpoint. 

### x-apple-aspen-deviceinfo Header

As part of that initial request, the device will send a `x-apple-aspen-deviceinfo` header. This contains a base64 encoded, signed plist, which contains information about the device defined by the [MachineInfo](https://developer.apple.com/documentation/devicemanagement/machineinfo?language=objc) object.

The plist is CMS (PKCS7) signed by a certificate chain that is rooted in [Apple's root certificate](https://www.apple.com/appleca/AppleIncRootCertificate.cer).

**Warning**: The information in this header, despite being signed by Apple PKI, shouldn't be trusted as device attestation. See [this article](https://duo.com/labs/research/mdm-me-maybe) for more information. Still, a valid header signature is useful information as part of authenticating the device, and dep-webview-oidc's default header parser configuration rejects requests with invalid header signatures.

#### Server Configuration:

The parser in webview-server can disable signature verification with `-header-verify-disabled`, and disable parsing the header completely with `header-parser-disabled`. Both of the flags are recommended only for debugging.

#### Library Configuration:

When using dep-webview-oidc as a library, you can configure the [`header.Parser`](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/header#Parser) with custom [`VerifyFunc`s](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/header#VerifyFunc), which allow for custom verification on the initial request and header, as well as passing additional context to later stages of the enrollment process. See [`header.MachineInfo.Context`](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/header#MachineInfo).

### OIDC State

Once the header passes verification, a random [`state`](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) is generated, which is associated with the parsed [`header.MachineInfo`](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/header#MachineInfo) in a state store.

#### Server Configuration:

webview-server includes an in-memory state store. 

The state expiration/time-to-live (TTL) can be configured with `-oidc-state-ttl`.

The state capacity (total number of active sessions) can be configured with `-oidc-state-capacity`.

#### Library Configuration:

When using dep-webview-oidc as a library, you can provide your own state store implementing [`store.StateStore`](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/store#StateStore).

### Redirect to OIDC Provider

Finally, the webview is redirected to the OIDC provider's authentication endpoint. The redirect URL is generated from the OIDC configuration and the state from above.

#### Server Configuration:

webview-server OIDC configuration is configured with the `-oidc-*` flags:

| Flag  | Usage |
| ----- | ----- |
| -oidc-disable       | If true, OIDC authentication is skipped completely and authentication only fails if header verification fails |
| -oidc-client-id     | The OIDC client ID |
| -oidc-client-secret | The OIDC client secret |
| -oidc-provider-url  | The OIDC provider URL |
| -oidc-redirect-url  | The URL base where the provider should redirect after successful authentication, e.g. "https://hostname[:port]", the base URL of webview-server itself |
| -oidc-scopes        | A list of comma separated OIDC scopes to include in flow. The openid scope will always be requested, e.g. "email, profile" |

#### Library Configuration:

When using dep-webview-oidc as a library, the OIDC configuration is configured on the Service with [`service.WithOIDCConfig`](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/service#WithOIDCConfig).

## OIDC Provider Auth

The authentication process for the OIDC provider is outside of the scope of dep-webview-oidc. If the provider does authenticate the webview session, it will redirect the webview to dep-webview-oidc's Callback Endpoint.

**Warning**: If you are configuring `anchor_certs` in the DEP profile (for self-signed certs or to pin the certificate), every host certificate the webview encounters (or their CA root) needs to be included, including the certificate for dep-webview-oidc (or TLS proxy in front), the OIDC provider, and any hosts the OIDC provider redirects through as part of their authentication process.

## Callback Endpoint

At the Callback Endpoint, the state (which is passed along by the OIDC provider) is used to find the matching [`header.MachineInfo`](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/header#MachineInfo) in the state store. 

The [OAuth 2.0 Exchange](https://datatracker.ietf.org/doc/html/rfc8693) is performed and the [OIDC `id_token`](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) is parsed from the OAuth 2.0 access token and verified against the OIDC configuration (see the [Redirect to OIDC Provider](#redirect-to-oidc-provider) section).

### Session Authorizer

The [`header.MachineInfo`](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/header#MachineInfo), OAuth 2.0 access token, and OIDC id_token are then passed to an [`auth.Authorizer`](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/auth#Authorizer) which will decide if the webview session is authorized or not. If it is authorized, the authorizer will return an optionally populated [`enrollprofile.Context`](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/enrollprofile#Context), which is passed to the [enrollment profile generator](#enrollment-profile-generator) in the next step.

> #### Why a Session Authorizer?
>
> OpenID Connect provides a protocol for authenticating users that is standard across all OIDC-compliant providers. However that standard doesn't include all of the information we may want to decide if a session is authorized, like if the user is in a particular security group, or has a certain attribute value.
>
> Users of dep-webview-oidc have two choices when implementing fine-grained authorization:
>
> 1. Use an OIDC provider that only authenticates users with desired attributes along with webview-server's default no-op authorizer
>    * This likely requires a custom OIDC provider (e.g. something like [ORY's Hydra](https://github.com/ory/hydra))
> 2. Write a custom [`auth.Authorizer`](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/auth#Authorizer) which authorizes the user via additional provider APIs. This implies writing your own custom server that uses dep-webview-oidc as a library

dep-webview-oidc includes a default [no-op authorizer](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/auth#NopAuthorizer), which authorizes all sessions, a [Google authorizer](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/auth/google#Authorizer) (see below), and [cache authorizer](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/auth#CacheAuthorizer) that wraps another authorizer and caches authorization results.

#### Server Configuration:

##### Google Authorizer

The built-in [Google Authorizer](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/auth/google) is simple example of a custom authorizer that uses the Google Admin SDK Directory API to only authorize users that are in specified Google Groups. The authorizer requires a Google OAuth 2.0 service account with Domain Wide Delegation enabled for the `https://www.googleapis.com/auth/admin.directory.group.member.readonly` scope. A user with read access to Groups in the Google Admin Console is required for impersonation to the API.

webview-server's Google Authorizer is configured with the `-google-*` flags:

| Flag  | Usage |
| ----- | ----- |
| -google-auth           | enables the Google Authorizer |
| -google-auth-path      | The path to a JSON OAuth 2.0 credentials file |
| -google-impersonate    | The email address of the impersonated user for API calls |
| -google-allowed-groups | A list of comma separated Google Groups (by email) that successful authentications will be authorized against, e.g. "admins@example.com, staff@example.com" |
| -google-worker-limit   | The limit of concurrent Google API requests (default 10) |

##### Authorizer Cache

webview-server's [Authorizer cache](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/auth#CacheAuthorizer) is configured with the `-cache-*` flags:

| Flag  | Usage |
| ----- | ----- |
| -auth-cache        | enables the Authorizer cache |
| -cache-success-ttl | The cache ttl of successful authorizations. This should be formatted as a Go duration, e.g. "10s", "15m", "4h", etc (default 10m0s) |
| -cache-failure-ttl | The cache ttl of failed authorizations. This should be formatted as a Go duration, e.g. "10s", "15m", "4h", etc (default 1m0s) |

#### Library Configuration:

When using dep-webview-oidc as a library, you can provide your own authorizer implementing [`auth.Authorizer`](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/auth#Authorizer).

### Enrollment Profile Generator

After authorization succeeds, the (possibly empty) [`enrollprofile.Context`](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/enrollprofile#Context) returned by the authorizer is given to the configured [`enrollprofile.Generator`](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/enrollprofile#Generator).

dep-webview-oidc includes a [file generator](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/enrollprofile#FileGenerator), which returns an enrollment profile from the filesystem as-is, a [signer generator](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/enrollprofile#Signer), which wraps a generator and signs its output, and a [MicroMDM SCEP Challenge generator](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/enrollprofile/micromdm#DynamicGenerator), which wraps a generator and inserts a dynamic SCEP challenge into its output from MicroMDM's challenge API (MicroMDM's `-use-dynamic-challenge` flag).

The enrollment profile returned from the generator is then returned to the client with the required `Content-Type: application/x-apple-aspen-config` header.

#### Server Configuration:

##### File Generator

webview-server's [file generator](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/enrollprofile#FileGenerator) is configured with the `-enroll-profile` flag, which is required. This generator reads the enrollment profile from the given file path every time a profile is requested.

##### Signer

webview-server's [signer generator](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/enrollprofile#Signer) is configured with the `-sign-identity` flag, which expects the file path to a .p12 (PKCS12) identity file like an Apple Developer identity. `-sign-identity-pass` can be used if the identity file is encrypted. If configured, generated enrollment profiles will be signed by the identity on the fly.

##### MicroMDM Dynamic SCEP Challenge

MicroMDM supports dynamic SCEP challenges with its `-use-dynamic-challenge` flag. If enabled, dep-webview-oidc will request a challenge from MicroMDM and insert the challenge into the profile returned by the wrapped generator. Once the client device receives the enrollment profile, it will use the dynamic SCEP challenge to get a certificate from MicroMDM's embedded SCEP server during the enrollment process.

webview-server's [MicroMDM SCEP Challenge generator](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/enrollprofile/micromdm#DynamicGenerator) is configured with these flags:

| Flag  | Usage |
| ----- | ----- |
| -dynamic-scep | enables the dynamic SCEP generator |
| -micromdm-url | The base URL of the MicroMDM server, e.g. "https://mdm.example.com" |
| -micromdm-key | The API key of the MicroMDM server |

#### Library Configuration:

When using dep-webview-oidc as a library, you can provide your own generator implementing [`enrollprofile.Generator`](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/enrollprofile#Generator). 

## When Things Go Wrong

If an error occurs in one of the Endpoints, it is passed to the Service's [`service.ErrorWriter`](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/service#ErrorWriter), which writes the error to the webview for the user to see.

#### Server Configuration:

webview-server includes a [text ErrorWriter](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/service#TextErrorWriter) which writes the HTTP status code and text to the webview page.

#### Library Configuration:

When using dep-webview-oidc as a library, you can provide your own ErrorWriter implementing [`service.ErrorWriter`](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/service#ErrorWriter). For example, you could implement an ErrorWriter that uses Go's `html/template` to output a nicely formatted HTML error page.

## Other Configuration

These are flags that are useful in the operation of webview-server. When using the library, these are available as [Service Options](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc/service#Option).

### Logging

dep-webview-oidc uses Go's `slog` structured logging library, and it outputs its logs in JSON-object-per-line format.

Use the `-log-level` flag to configure the level of logging (e.g. DEBUG, INFO, WARN, ERROR).

Use the `-log-output` flag to output the logs to a file instead of stdout which is default.

### TLS

webview-server supports TLS with the `-tls-cert` and `-tls-key` flags. The cert (or cert chain if an intermediate certificate is used) and key must be in PEM format.

### Proxy Support

webview-server supports running behind a proxy. Use the `-proxy-headers` flag to parse proxy headers and update IP information (i.e. to show the "real" IP in the logs).

Use the `-url-prefix` flag to add a prefix to the Endpoint URLs. e.g. `-url-prefix=/dep` means the Authorize Endpoint is now `https://example.tld/dep/v1/authorize`.
