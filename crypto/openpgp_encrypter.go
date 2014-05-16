package crypto

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"errors"
	"io"
	"io/ioutil"
)

type KeyNotFoundError string

func (e KeyNotFoundError) Error() string {
	return "Key not found for '" + string(e) + "'"
}

type OpenPgPEncrypter struct {
	pubKeyRing openpgp.EntityList
}

type encryptFunction func(writeCloser io.WriteCloser) (io.WriteCloser, error)

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
	recipients, err := e.recipients(to)
	if err != nil {
		return "", err
	}
	return encrypt(reader, func(writeCloser io.WriteCloser) (io.WriteCloser, error) {
		return openpgp.Encrypt(writeCloser, recipients, nil, nil, nil)
	})
}

func (e *OpenPgPEncrypter) EncryptForHidden(reader io.Reader, to []string) (string, error) {
	if len(to) == 0 {
		return "", errors.New("Missing recipient")
	}
	recipients, err := e.recipients(to)
	if err != nil {
		return "", err
	}
	fingerprintKeyMap := make(map[[20]byte]uint64)
	for _, entity := range recipients {
		for _, s := range entity.Subkeys {
			fingerprintKeyMap[s.PublicKey.Fingerprint] = s.PublicKey.KeyId
			s.PublicKey.KeyId = uint64(0)
		}
	}
	defer func() {
		for _, entity := range recipients {
			for _, s := range entity.Subkeys {
				s.PublicKey.KeyId = fingerprintKeyMap[s.PublicKey.Fingerprint]
			}
		}
	}()
	return encrypt(reader, func(writeCloser io.WriteCloser) (io.WriteCloser, error) {
		return openpgp.Encrypt(writeCloser, recipients, nil, nil, nil)
	})
}

func encrypt(reader io.Reader, encryptor encryptFunction) (string, error) {
	message, err := ioutil.ReadAll(reader)
	if err != nil {
		return "", err
	}
	textBuffer := new(bytes.Buffer)
	armoredWriteCloser, err := armor.Encode(textBuffer, "PGP MESSAGE", nil)
	writeCloser, err := encryptor(armoredWriteCloser)
	if err != nil {
		return "", err
	}
	writeCloser.Write(message)
	writeCloser.Close()
	armoredWriteCloser.Close()
	return textBuffer.String(), nil
}

func (e *OpenPgPEncrypter) recipients(to []string) ([]*openpgp.Entity, error) {
	recipients := make([]*openpgp.Entity, 0)
	for _, email := range to {
		entity := getEntityForEmail(e.pubKeyRing, email)
		if entity == nil {
			return nil, KeyNotFoundError(email)
		}
		recipients = append(recipients, entity)
	}
	return recipients, nil
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
