package crypto

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
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
	return e.encrypt(reader, func(writeCloser io.WriteCloser) (io.WriteCloser, error) {
		return openpgp.SymmetricallyEncrypt(writeCloser, password, nil, nil)
	})
}

func (e *OpenPgPEncrypter) EncryptFor(reader io.Reader, to []string) (encryptedMessage string, err error) {
	receipients := make([]*openpgp.Entity, 0)
	for _, email := range to {
		entity := getEntityForEmail(e.pubKeyRing, email)
		if entity == nil {
			err = KeyNotFoundError(email)
		} else {
			receipients = append(receipients, entity)
		}
	}
	if len(receipients) == 0 {
		return
	}
	return e.encrypt(reader, func(writeCloser io.WriteCloser) (io.WriteCloser, error) {
		return openpgp.Encrypt(writeCloser, receipients, nil, nil, nil)
	})
}

func (e *OpenPgPEncrypter) encrypt(reader io.Reader, encryptFunction func(writeCloser io.WriteCloser) (io.WriteCloser, error)) (encryptedMessage string, err error) {
	message, err := ioutil.ReadAll(reader)
	if err != nil {
		return
	}
	textBuffer := new(bytes.Buffer)
	armoredWriteCloser, err := armor.Encode(textBuffer, "PGP MESSAGE", nil)
	writeCloser, err := encryptFunction(armoredWriteCloser)
	if err != nil {
		return
	}
	writeCloser.Write(message)
	writeCloser.Close()
	armoredWriteCloser.Close()
	encryptedMessage = textBuffer.String()
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
