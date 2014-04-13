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
		return encryptedMessage, err
	}
	message, err := ioutil.ReadAll(reader)
	if err != nil {
		return encryptedMessage, err
	}
	textBuffer := new(bytes.Buffer)
	armoredWriteCloser, err := armor.Encode(textBuffer, "PGP MESSAGE", nil)
	writeCloser, err := openpgp.Encrypt(armoredWriteCloser, receipients, nil, nil, nil)
	if err != nil {
		return encryptedMessage, err
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
