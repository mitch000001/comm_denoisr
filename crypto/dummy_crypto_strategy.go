package crypto

import (
	"io"
)

type DummyCryptoStrategy struct {
	DummyEncrypter
	DummyDecrypter
}

type DummyEncrypter struct{}

func (this *DummyEncrypter) Encrypt(message io.Reader, password string) (string, error) {
	return "", nil
}

func (this *DummyEncrypter) EncryptFor(message io.Reader, to []string) (string, error) {
	return "", nil
}

func (this *DummyEncrypter) EncryptForHidden(message io.Reader, to []string) (string, error) {
	return "", nil
}

type DummyPlain struct {
	body     io.Reader
	isBinary bool
	fileName string
}

func (this *DummyPlain) Body() io.Reader {
	return nil
}

func (this *DummyPlain) IsBinary() bool {
	return false
}

func (this *DummyPlain) FileName() string {
	return ""
}

type DummyDecrypter struct{}

func (this *DummyDecrypter) Decrypt(message io.Reader) (Plain, error) {
	return &DummyPlain{}, nil
}

func (this *DummyDecrypter) CanDecrypt(message io.Reader) (bool, io.Reader) {
	return false, nil
}

type DummySigner struct{}

func (this *DummySigner) Sign(message io.Reader) (io.Reader, error) {
	return nil, nil
}
