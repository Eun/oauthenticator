# oauthenticator
[![Actions Status](https://github.com/Eun/oauthenticator/workflows/push/badge.svg)](https://github.com/Eun/oauthenticator/actions)
[![Coverage Status](https://coveralls.io/repos/github/Eun/oauthenticator/badge.svg?branch=main)](https://coveralls.io/github/Eun/oauthenticator?branch=main)
[![PkgGoDev](https://img.shields.io/badge/pkg.go.dev-reference-blue)](https://pkg.go.dev/github.com/Eun/oauthenticator)
[![go-report](https://goreportcard.com/badge/github.com/Eun/oauthenticator)](https://goreportcard.com/report/github.com/Eun/oauthenticator)
---
A package to help with oauth authentication.

### Usage
```go
client, err := oauthenticator.Authorize(
    oauthenticator.ClientID("client_id"),
    oauthenticator.ClientSecret("client_secret"),
    oauthenticator.Scopes("https://www.googleapis.com/auth/youtube"),
    oauthenticator.AuthURL("https://accounts.google.com/o/oauth2/auth"),
    oauthenticator.TokenURL("https://accounts.google.com/o/oauth2/token"),
    oauthenticator.TokenFile("google.token.json"),
)
```
The package will start a http server on `:8000` and will wait for the code.
You can tweak that by using `RedirectAddress` and `LocalBindAddress`.


## Build History
[![Build history](https://buildstats.info/github/chart/Eun/oauthenticator?branch=main)](https://github.com/Eun/go-bin-template/actions)
