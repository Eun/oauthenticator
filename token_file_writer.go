package oauthenticator

import "os"

type tokenFileWriter struct {
	file       string
	fileHandle *os.File
}

func (t *tokenFileWriter) Write(p []byte) (int, error) {
	if t.fileHandle == nil {
		var err error
		t.fileHandle, err = os.Create(t.file)
		if err != nil {
			return 0, err
		}
	}
	return t.fileHandle.Write(p)
}
func (t *tokenFileWriter) Close() error {
	if t.fileHandle == nil {
		return nil
	}
	err := t.fileHandle.Close()
	t.fileHandle = nil
	return err
}
