package crypto

import (
	"io"
)

type CryptoType string

type CryptoStrategy interface {
	Encrypter
	Decrypter
}

type Encrypted interface {
	// Returns the type of the encrypted data to use the right decrypter
	Type() CryptoType
	// Returns the actual encrypted content
	Body() io.Reader
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
	Decrypt(Encrypted) (Plain, error)
	// Returns true if the provided reader is decryptable by the
	// decrypter. Note that the reader will get consumed.
	// Returns also a new reader with the contents read from the
	// input reader
	CanDecrypt(io.Reader) (bool, io.Reader)
	// Reads the given Reader and returns an Encrypted to pass in #Decrypt
	// An implementation should call #CanDecrypt before or within that function
	// The given reader can't be used after Read has run on it
	Read(io.Reader) (Encrypted, error)
}

type Signer interface {
	// Signs the message and returns the signature
	Sign(message io.Reader) (io.Reader, error)
}
