package oauthenticator

import (
	"context"
	"io"
)

type Option func(authorizer *authorizer) error

func Context(ctx context.Context) Option {
	return func(authorizer *authorizer) error {
		authorizer.ctx = ctx
		return nil
	}
}

func ClientID(clientID string) Option {
	return func(authorizer *authorizer) error {
		authorizer.clientID = clientID
		return nil
	}
}
func ClientSecret(clientSecret string) Option {
	return func(authorizer *authorizer) error {
		authorizer.clientSecret = clientSecret
		return nil
	}
}

func AuthURL(authURL string) Option {
	return func(authorizer *authorizer) error {
		authorizer.authURL = authURL
		return nil
	}
}
func TokenURL(tokenURL string) Option {
	return func(authorizer *authorizer) error {
		authorizer.tokenURL = tokenURL
		return nil
	}
}

func Scopes(scopes ...string) Option {
	return func(authorizer *authorizer) error {
		authorizer.scopes = scopes
		return nil
	}
}

func RedirectAddress(address string) Option {
	return func(authorizer *authorizer) error {
		authorizer.redirectAddress = address
		return nil
	}
}

func LocalBindAddress(address string) Option {
	return func(authorizer *authorizer) error {
		authorizer.localBindAddress = address
		return nil
	}
}

func TokenReader(r io.Reader) Option {
	return func(authorizer *authorizer) error {
		authorizer.tokenReader = r
		return nil
	}
}

func TokenWriter(w io.Writer) Option {
	return func(authorizer *authorizer) error {
		authorizer.tokenWriter = w
		return nil
	}
}

func TokenFile(file string) Option {
	return func(authorizer *authorizer) error {
		authorizer.tokenReader = &tokenFileReader{file: file}
		authorizer.tokenWriter = &tokenFileWriter{file: file}
		return nil
	}
}

func AuthorizeService(fn AuthorizeServiceHandler) Option {
	return func(authorizer *authorizer) error {
		authorizer.authorizeService = fn
		return nil
	}
}
