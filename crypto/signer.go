package crypto

import (
	"io"
)

type Signer interface {
	// Signs the message and returns the signature
	Sign(message io.Reader) (io.Reader, error)
}

type NoOpSigner struct{}

func (this *NoOpSigner) Sign(message io.Reader) (io.Reader, error) {
	return message, nil
}
