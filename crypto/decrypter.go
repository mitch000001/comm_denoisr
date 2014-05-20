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
	// Decrypts the given reader and returns a Plain with the content
	// and corresponding metadata
	Decrypt(io.Reader) (Plain, error)
	// Returns true if the provided reader is decryptable by the
	// decrypter. Note that the reader will get consumed.
	// Returns also a new reader with the contents read from the
	// input reader
	CanDecrypt(io.Reader) (bool, io.Reader)
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
