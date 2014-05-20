package crypto

import (
	"io"
)

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
