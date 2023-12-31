package oauthenticator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

type AuthorizeServiceHandler func(ctx context.Context, url string) error

type authorizer struct {
	ctx              context.Context
	clientID         string
	clientSecret     string
	scopes           []string
	authURL          string
	tokenURL         string
	redirectAddress  string
	localBindAddress string

	tokenReader      io.Reader
	tokenWriter      io.Writer
	authorizeService AuthorizeServiceHandler
}

func Authorize(options ...Option) (*http.Client, error) {
	var a authorizer
	for _, option := range options {
		if err := option(&a); err != nil {
			return nil, fmt.Errorf("unable to apply option: %w", err)
		}
	}

	if a.ctx == nil {
		a.ctx = context.Background()
	}

	if a.redirectAddress == "" {
		a.redirectAddress = "http://127.0.0.1:8000"
	}
	if a.localBindAddress == "" {
		a.localBindAddress = ":8000"
	}
	if a.authorizeService == nil {
		a.authorizeService = func(ctx context.Context, url string) error {
			fmt.Println("Please open", url)
			fmt.Println("Waiting for authorization...")
			return nil
		}
	}

	var tokenBuf []byte
	if a.tokenReader != nil {
		var err error
		tokenBuf, err = io.ReadAll(a.tokenReader)
		if err != nil {
			return nil, fmt.Errorf("unable to read token")
		}

		if closer, ok := a.tokenReader.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				return nil, fmt.Errorf("unable to close token reader")
			}
		}
	}

	oauthConfig := a.createOauthConfig()
	shouldWriteToken := false
	if len(tokenBuf) == 0 {
		var err error
		tokenBuf, err = a.fetchNewToken(oauthConfig)
		if err != nil {
			return nil, fmt.Errorf("unable to fetch new token: %w", err)
		}
		shouldWriteToken = true
	}
	oauth2Token, err := a.decodeOauthToken(tokenBuf)
	if err != nil {
		return nil, fmt.Errorf("unable to decode token: %w", err)
	}

	tokenSource := oauthConfig.TokenSource(a.ctx, oauth2Token)
	updatedOauth2Token, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("unable to get token: %w", err)
	}

	client := oauth2.NewClient(a.ctx, tokenSource)
	if updatedOauth2Token.AccessToken != oauth2Token.AccessToken {
		shouldWriteToken = true
	}
	if shouldWriteToken && a.tokenWriter != nil {
		buf, err := json.Marshal(updatedOauth2Token)
		if err != nil {
			return nil, fmt.Errorf("unable to encode token: %w", err)
		}
		if _, err = a.tokenWriter.Write(buf); err != nil {
			return nil, fmt.Errorf("unable to write token: %w", err)
		}
		if closer, ok := a.tokenWriter.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				return nil, fmt.Errorf("unable to close token writer")
			}
		}
	}

	return client, nil
}

func (a *authorizer) fetchNewToken(oauthConfig *oauth2.Config) ([]byte, error) {
	var buf [128]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return nil, fmt.Errorf("unable to read from crypto")
	}
	state := hex.EncodeToString(buf[:])
	codeChan := make(chan string)
	errChan := make(chan error)
	var httpServer http.Server
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("state") != state {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, "state mismatch")
				return
			}
			if s := r.URL.Query().Get("error"); s != "" {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintf(w, "error: %s", s)
				return
			}
			code := r.URL.Query().Get("code")
			if code == "" {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, "code is missing")
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "authorized, you can close this window.")
			codeChan <- code
		})
		httpServer.Addr = a.localBindAddress
		httpServer.Handler = mux
		errChan <- httpServer.ListenAndServe()
	}()

	authURL := oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)

	if err := a.authorizeService(a.ctx, authURL); err != nil {
		return nil, fmt.Errorf("unable to handle authorization url")
	}

	var code string
	select {
	case c := <-codeChan:
		code = c
	case err := <-errChan:
		return nil, fmt.Errorf("unable to listen on http server: %w", err)
	}
	_ = httpServer.Close()

	tkn, err := oauthConfig.Exchange(a.ctx, strings.TrimSpace(code))
	if err != nil {
		return nil, fmt.Errorf("unable to exchange token: %w", err)
	}
	if !tkn.Valid() {
		return nil, fmt.Errorf("got the token, but its invalid")
	}
	tokenBuf, err := json.Marshal(tkn)
	if err != nil {
		return nil, fmt.Errorf("unable to encode token: %w", err)
	}
	return tokenBuf, nil
}

func (a *authorizer) createOauthConfig() *oauth2.Config {
	return &oauth2.Config{
		Scopes:      a.scopes,
		RedirectURL: a.redirectAddress,
		Endpoint: oauth2.Endpoint{
			AuthURL:  a.authURL,
			TokenURL: a.tokenURL,
		},
		ClientID:     a.clientID,
		ClientSecret: a.clientSecret,
	}
}

func (a *authorizer) decodeOauthToken(buf []byte) (*oauth2.Token, error) {
	var token oauth2.Token
	if err := json.Unmarshal(buf, &token); err != nil {
		return nil, err
	}
	return &token, nil
}
