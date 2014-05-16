package crypto

import (
	"io"
)

// Plain represents the decrypted data
type Plain interface {
	// Returns the raw body of the decrypted content
	Body() io.Reader
	// Returns whether the decrypted content is binary or not
	IsBinary() bool
	// Returns the filename of the decrypted content
	FileName() string
}

type Decrypter interface {
	Decrypt(io.Reader) (Plain, error)
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
