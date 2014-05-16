package crypto

import (
	"io"
	"io/ioutil"
)

type Encrypter interface {
	// Encrypt the given message with the provided password
	// Returns the encrypted message or an error
	Encrypt(message io.Reader, password string) (string, error)
	// Encrypt the given message for all recipients in to
	// Returns the encrypted message or an error
	EncryptFor(message io.Reader, to []string) (string, error)
	// Encrypt the given message for all recipients in to and hides the recipients in the encrypted message
	// Returns the encrypted message or an error
	EncryptForHidden(message io.Reader, to []string) (string, error)
}

type NoOpEncrypter struct{}

func (this *NoOpEncrypter) Encrypt(message io.Reader, password string) (string, error) {
	messageBytes, err := ioutil.ReadAll(message)
	if err != nil {
		return "", err
	}
	return string(messageBytes), nil
}

func (this *NoOpEncrypter) EncryptFor(message io.Reader, to []string) (string, error) {
	return this.Encrypt(message, "")
}

func (this *NoOpEncrypter) EncryptForHidden(message io.Reader, to []string) (string, error) {
	return this.Encrypt(message, "")
}
