package crypto

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	_ "code.google.com/p/go.crypto/openpgp/armor"
	_ "code.google.com/p/go.crypto/openpgp/errors"
	"io"
	"io/ioutil"
)

type Encrypter interface {
	Encrypt(message io.Reader, password []byte) (string, error)
	EncryptFor(message io.Reader, to []Receipient) (string, error)
}

type Receipient interface{}

type OpenPgPEncrypter struct {
	pubKeyRing openpgp.KeyRing
}

func (e *OpenPgPEncrypter) Encrypt(reader io.Reader, password []byte) (encryptedMessage string, err error) {
	message, err := ioutil.ReadAll(reader)
	if err != nil {
		return encryptedMessage, err
	}
	cipherBuffer := new(bytes.Buffer)
	writeCloser, err := openpgp.SymmetricallyEncrypt(cipherBuffer, password, nil, nil)
	if err != nil {
		return encryptedMessage, err
	}
	writeCloser.Write(message)
	writeCloser.Close()
	encryptedMessage = string(cipherBuffer.Bytes())
	return
}

func (e *OpenPgPEncrypter) EncryptFor(reader io.Reader, to []*openpgp.Entity) (encryptedMessage string, err error) {
	message, err := ioutil.ReadAll(reader)
	if err != nil {
		return encryptedMessage, err
	}
	cipherBuffer := new(bytes.Buffer)
	writeCloser, err := openpgp.Encrypt(cipherBuffer, to, nil, nil, nil)
	if err != nil {
		return encryptedMessage, err
	}
	writeCloser.Write(message)
	writeCloser.Close()
	encryptedMessage = string(cipherBuffer.Bytes())
	return
}
