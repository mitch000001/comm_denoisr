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
	// Encrypt the given message for all receipients in to
	// Returns the encrypted message or an error
	EncryptFor(message io.Reader, to []string) (string, error)
}

type OpenPgPEncrypter struct {
	pubKeyRing openpgp.EntityList
}

func NewOpenPgPEncrypter(pubKeyRing openpgp.EntityList) Encrypter {
	return &OpenPgPEncrypter{pubKeyRing: pubKeyRing}
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

func (e *OpenPgPEncrypter) EncryptFor(reader io.Reader, to []string) (encryptedMessage string, err error) {
	receipients := make([]*openpgp.Entity, len(to))
	for i, _ := range to {
		// TODO: add error handling, we can't know the content of 'to'
		receipients[i] = getEntityForEmail(e.pubKeyRing, to[i])
	}
	message, err := ioutil.ReadAll(reader)
	if err != nil {
		return encryptedMessage, err
	}
	cipherBuffer := new(bytes.Buffer)
	writeCloser, err := openpgp.Encrypt(cipherBuffer, receipients, nil, nil, nil)
	if err != nil {
		return encryptedMessage, err
	}
	writeCloser.Write(message)
	writeCloser.Close()
	encryptedMessage = string(cipherBuffer.Bytes())
	return
}

func getEntityForEmail(keyring openpgp.EntityList, email string) *openpgp.Entity {
	for _, entity := range keyring {
		for _, ident := range entity.Identities {
			if ident.UserId.Email == email {
				return entity
			}
		}
	}

	return nil
}
