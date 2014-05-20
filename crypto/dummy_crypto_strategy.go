package crypto

import (
	"io"
)

type NoOpCryptoStrategy struct {
	NoOpEncrypter
	NoOpDecrypter
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

type NoOpPlain struct {
	body     io.Reader
	isBinary bool
	fileName string
}

func (this *NoOpPlain) Body() io.Reader {
	return this.body
}

func (this *NoOpPlain) IsBinary() bool {
	return this.isBinary
}

func (this *NoOpPlain) FileName() string {
	return this.fileName
}

type NoOpDecrypter struct{}

func (this *NoOpDecrypter) Decrypt(message io.Reader) (Plain, error) {
	return &NoOpPlain{body: message, isBinary: false, fileName: ""}, nil
}

func (this *NoOpDecrypter) CanDecrypt(message io.Reader) (bool, io.Reader) {
	return true, message
}

type NoOpSigner struct{}

func (this *NoOpSigner) Sign(message io.Reader) (io.Reader, error) {
	return message, nil
}
