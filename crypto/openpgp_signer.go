package crypto

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"io"
)

type OpenPgpSigner struct {
	signer *openpgp.Entity
}

func (s *OpenPgpSigner) Sign(message io.Reader) (io.Reader, error) {
	textBuffer := new(bytes.Buffer)
	err := openpgp.ArmoredDetachSign(textBuffer, s.signer, message, nil)
	if err != nil {
		return nil, err
	}
	return textBuffer, nil
}
