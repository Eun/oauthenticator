package oauthenticator

import (
	"errors"
	"io"
	"os"
)

type tokenFileReader struct {
	file       string
	fileHandle *os.File
}

func (t *tokenFileReader) Read(p []byte) (n int, err error) {
	if t.fileHandle == nil {
		var err error
		t.fileHandle, err = os.Open(t.file)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return 0, io.EOF
			}
			return 0, err
		}
	}

	return t.fileHandle.Read(p)
}

func (t *tokenFileReader) Close() error {
	if t.fileHandle == nil {
		return nil
	}
	err := t.fileHandle.Close()
	t.fileHandle = nil
	return err
}
