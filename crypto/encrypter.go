package crypto

import (
	_ "code.google.com/p/go.crypto/openpgp"
	_ "code.google.com/p/go.crypto/openpgp/armor"
	_ "code.google.com/p/go.crypto/openpgp/errors"
	"io"
)

type Encrypter interface {
	Encrypt(io.Reader) (string, error)
}

type EncryptedMessage string

func (e *EncryptedMessage) Write(p []byte) (n int, err error) {
	return
}

func (e *EncryptedMessage) Read(p []byte) (n int, err error) {
	return
}

type OpenPgPEncrypter struct {
}

func (e *OpenPgPEncrypter) Encrypt(reader io.Reader) (encryptedMessage string, err error) {
	return
}
