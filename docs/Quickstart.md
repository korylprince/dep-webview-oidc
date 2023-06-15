# Quickstart Guide

This quickstart guide will walk you through the basic configuration of webview-server.

## Requirements

* Access to Apple's Device Enrollment Program (DEP)
* A Mac in your DEP account with at least macOS 10.15
* An MDM server that allows configuring the `configuration_web_url` key of the DEP profile
  * [MicroMDM](https://github.com/micromdm/micromdm) and [NanoDEP](https://github.com/micromdm/nanodep) are two open source options
* Your MDM's enrollment profile
* An OpenID Connect Provider and client credentials
* A TLS certificate and key signed by a trusted CA, or run behind a reverse proxy with a TLS certificate signed by a trusted CA

### Recommended

* An Apple Developer identity file (.p12), e.g. A Developer ID Installer identity

## Download 

Download a pre-built binary from the [Releases page](https://github.com/korylprince/dep-webview-oidc/releases). Rename the binary to "webview-server".

You can also the [container](https://github.com/korylprince/dep-webview-oidc/pkgs/container/dep-webview-oidc), but make sure any files you want to use (enrollment profile, developer identity) are accessible in the container.

## First Run

Create a directory with the following files:

```
/
  webview-server (binary you downloaded)
  enrollment.mobileconfig (your MDM enrollment profile)
  cert.pem (TLS cert)
  key.pem (TLS key)
  signing_identity.p12 (optional, your Apple Developer identity file)
```

In that directory, execute:

`$ ./webview-server -oidc-disable -header-parser-disabled -listen-addr ":8080" -enroll-profile ./enrollment.mobileconfig`

You'll see some initial log output. Open a browser on the same device and navigate to http://localhost:8080/v1/authorize. Your browser should download a file which matches your enrollment profile. Success, but a little boring. By using the -oidc-disable and -header-parser-disabled, we've disabled all authentication.

## Configure OIDC

Let's connect webview-server to our OIDC provider:

```$ ./webview-server \
  -header-parser-disabled \
  -listen-addr ":8080" \
  -enroll-profile ./enrollment.mobileconfig` \
  -oidc-provider-url "your provider url" \ 
  -oidc-client-id "your OIDC client id" \
  -oidc-client-secret "your OIDC client secret" \
  -oidc-redirect-url-base "http://localhost:8080"
```

*Note: you may need to configure your OIDC provider to all a callback URL of "http://localhost:8080/v1/callback" if it filters callback URLs.

Now if you navigate your browser to http://localhost:8080/v1/authorize, you should be redirected to your OIDC provider's authentication page. Authenticate with your provider, and you should be redirected to http://localhost:8080/v1/callback where your enrollment profile will be downloaded again.

## Real World Example

There's nothing left to do but enroll an actual device. You'll need to run webview-server with a trusted TLS certificate. For this example we'll say our server has a certificate for dep.example.com.

*Note: By trusted certificate, we mean a certificate trusted by your testing Mac*

First, configure your DEP profile with `configuration_web_url = https://dep.example.com/v1/authorize` and assign it to your test Mac. Now, run webview-server:

```$ ./webview-server \
  -tls-cert ./cert.pem \
  -tls-key ./key.pem \
  -enroll-profile ./enrollment.mobileconfig` \
  -oidc-provider-url "your provider url" \ 
  -oidc-client-id "your OIDC client id" \
  -oidc-client-secret "your OIDC client secret" \
  -oidc-redirect-url-base "https://dep.example.com"
```

Now trigger a DEP enrollment on your test Mac by running `sudo profiles renew -type enrollment`, click the enrollment notification, and follow the prompts in System Preferences. Eventually, a webview should pop up, and it should redirect to your OIDC provider's authentication page. In the logs, you should see an entry with your Mac's serial number. Authenticate with your provider and the webview should close, with the enrollment profile getting installed. 🎉

#### Troubleshooting

* The `sudo profiles renew -type enrollment` command didn't trigger a notification
  * Are you sure your Mac has a DEP profile assigned?
  * Do you have do not disturb turned on, blocking notifications?
  * Try unenrolling the device from your MDM if it's currently enrolled
* The webview shows a certificate error
  * Are you using a certificate trusted by your Mac? e.g. can you browse to https://dep.example.com/v1/authorize on the Mac and not get a certificate error?
  * Are you using `anchor_certs` in your DEP profile? It must included the cert for every page the webview goes to, not just for your TLS cert
* The webview shows an error message
  * Does browsing to https://dep.example.com/v1/authorize in a browser on the test Mac generate a log message in webview-server's output? If not, dep.example.com is not resolving to your server in your DNS
  * Check the webview-server logs for an error messages indicating the problem
* The enrollment profile doesn't install
  * Are you sure the enrollment profile is valid? Will it install by double clicking it on the test Mac?

## MicroMDM Dynamic SCEP Challenges and Signed Enrollment Profiles

Let's go all out. If you're running MicroMDM, you can turn on dynamic SCEP challeges by adding the `-use-dynamic-challenge` to MicroMDM. While we're at it, let's also sign the enrollment profile with our developer identity.

```$ ./webview-server \
  -tls-cert ./cert.pem \
  -tls-key ./key.pem \
  -enroll-profile ./enrollment.mobileconfig` \
  -oidc-provider-url "your provider url" \ 
  -oidc-client-id "your OIDC client id" \
  -oidc-client-secret "your OIDC client secret" \
  -oidc-redirect-url-base "https://dep.example.com"
  -dynamic-scep \
  -micromdm-url "https://micromdm.example.com" \
  -micromdm-key "your micromdm api key" \
  -sign-identity ./signing_identity.p12 \
  -sign-identity-pass "your identity password"
```

*Note: leave off the `-sign-identity-pass` flag if your identity file doesn't have a password.*

Now follow the same DEP enrollment process as in [Real World Example](#real-world-example), and you should end up enrolled with a signed enrollment profile. 🎉

## Next Steps

* View the [Architecture Guide](https://github.com/korylprince/dep-webview-oidc/tree/master/docs/Architecture.md) for an in-depth explanation of dep-webview-oidc's inner workings
* View the [package documentation](https://pkg.go.dev/github.com/korylprince/dep-webview-oidc) to start writing your own custom authorization code
