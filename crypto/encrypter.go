package crypto

import (
	"io"
	"io/ioutil"
)

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
