package main

import (
	"io"
)

type CryptoStrategy interface {
	Encrypter
	Decrypter
}

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

type Signer interface {
	// Signs the message and returns the signature
	Sign(message io.Reader) (io.Reader, error)
}
