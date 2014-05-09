package crypto

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"errors"
	"io"
	"io/ioutil"
)

type Encrypter interface {
	Encrypt(message io.Reader, password string) (string, error)
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

func (e *OpenPgPEncrypter) Encrypt(reader io.Reader, password string) (string, error) {
	return encrypt(reader, func(writeCloser io.WriteCloser) (io.WriteCloser, error) {
		return openpgp.SymmetricallyEncrypt(writeCloser, []byte(password), nil, nil)
	})
}

func (e *OpenPgPEncrypter) EncryptFor(reader io.Reader, to []string) (string, error) {
	if len(to) == 0 {
		return "", errors.New("Missing recipient")
	}
	receipients := make([]*openpgp.Entity, 0)
	for _, email := range to {
		entity := getEntityForEmail(e.pubKeyRing, email)
		if entity == nil {
			return "", KeyNotFoundError(email)
		}
		receipients = append(receipients, entity)
	}
	return encrypt(reader, func(writeCloser io.WriteCloser) (io.WriteCloser, error) {
		return openpgp.Encrypt(writeCloser, receipients, nil, nil, nil)
	})
}

func encrypt(reader io.Reader, encryptFunction func(writeCloser io.WriteCloser) (io.WriteCloser, error)) (string, error) {
	message, err := ioutil.ReadAll(reader)
	if err != nil {
		return "", err
	}
	textBuffer := new(bytes.Buffer)
	armoredWriteCloser, err := armor.Encode(textBuffer, "PGP MESSAGE", nil)
	writeCloser, err := encryptFunction(armoredWriteCloser)
	if err != nil {
		return "", err
	}
	writeCloser.Write(message)
	writeCloser.Close()
	armoredWriteCloser.Close()
	return textBuffer.String(), nil
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
