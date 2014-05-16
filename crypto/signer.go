package crypto

import (
	"io"
)

type Signer interface {
	Sign(message io.Reader) io.Reader
}

type NoOpSigner struct{}

func (this *NoOpSigner) Sign(message io.Reader) io.Reader {
	return message
}
