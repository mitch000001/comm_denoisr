package crypto

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	openpgpErrors "code.google.com/p/go.crypto/openpgp/errors"
	"code.google.com/p/go.crypto/openpgp/packet"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
)

type OpenPgpCryptoStrategy struct {
	OpenPgPEncrypter
	OpenPgPDecrypter
}

func NewOpenPgpCryptoStrategy(keyring openpgp.EntityList, promptFunction openpgp.PromptFunction) CryptoStrategy {
	e := OpenPgPEncrypter{keyring}
	d := OpenPgPDecrypter{}
	d.privateKeyRing = keyring
	d.alreadyPromptedKeys = make(map[[20]byte]struct{})
	if promptFunction != nil {
		d.promptFunction = promptFunction
	} else {
		d.promptFunction = getBashPromptForPassword(&d)
	}
	return &OpenPgpCryptoStrategy{e, d}
}

type KeyNotFoundError string

func (e KeyNotFoundError) Error() string {
	return "Key not found for '" + string(e) + "'"
}

type OpenPgPEncrypter struct {
	pubKeyRing openpgp.EntityList
}

func NewOpenPgPEncrypter(pubKeyRing openpgp.EntityList) Encrypter {
	return &OpenPgPEncrypter{pubKeyRing: pubKeyRing}
}

func (e *OpenPgPEncrypter) Encrypt(reader io.Reader, password string) (string, error) {
	return encrypt(reader, func(writeCloser io.WriteCloser) (io.WriteCloser, error) {
		return openpgp.SymmetricallyEncrypt(writeCloser, []byte(password), nil, nil)
	})
}

func (e *OpenPgPEncrypter) EncryptFor(reader io.Reader, to []string) (string, error) {
	if len(to) == 0 {
		return "", errors.New("Missing recipient")
	}
	recipients, err := e.recipients(to)
	if err != nil {
		return "", err
	}
	return encrypt(reader, func(writeCloser io.WriteCloser) (io.WriteCloser, error) {
		return openpgp.Encrypt(writeCloser, recipients, nil, nil, nil)
	})
}

func (e *OpenPgPEncrypter) EncryptForHidden(reader io.Reader, to []string) (string, error) {
	if len(to) == 0 {
		return "", errors.New("Missing recipient")
	}
	recipients, err := e.recipients(to)
	if err != nil {
		return "", err
	}
	fingerprintKeyMap := make(map[[20]byte]uint64)
	for _, entity := range recipients {
		for _, s := range entity.Subkeys {
			fingerprintKeyMap[s.PublicKey.Fingerprint] = s.PublicKey.KeyId
			s.PublicKey.KeyId = uint64(0)
		}
	}
	defer func() {
		for _, entity := range recipients {
			for _, s := range entity.Subkeys {
				s.PublicKey.KeyId = fingerprintKeyMap[s.PublicKey.Fingerprint]
			}
		}
	}()
	return encrypt(reader, func(writeCloser io.WriteCloser) (io.WriteCloser, error) {
		return openpgp.Encrypt(writeCloser, recipients, nil, nil, nil)
	})
}

type encryptFunction func(writeCloser io.WriteCloser) (io.WriteCloser, error)

func encrypt(reader io.Reader, encryptor encryptFunction) (string, error) {
	message, err := ioutil.ReadAll(reader)
	if err != nil {
		return "", err
	}
	textBuffer := new(bytes.Buffer)
	armoredWriteCloser, err := armor.Encode(textBuffer, "PGP MESSAGE", nil)
	writeCloser, err := encryptor(armoredWriteCloser)
	if err != nil {
		return "", err
	}
	writeCloser.Write(message)
	writeCloser.Close()
	armoredWriteCloser.Close()
	return textBuffer.String(), nil
}

func (e *OpenPgPEncrypter) recipients(to []string) ([]*openpgp.Entity, error) {
	recipients := make([]*openpgp.Entity, 0)
	for _, email := range to {
		entity := getEntityForEmail(e.pubKeyRing, email)
		if entity == nil {
			return nil, KeyNotFoundError(email)
		}
		recipients = append(recipients, entity)
	}
	return recipients, nil
}

func getEntityForEmail(keyring openpgp.EntityList, email string) *openpgp.Entity {
	for _, entity := range keyring {
		for _, ident := range entity.Identities {
			if ident.UserId.Email == email {
				return entity
			}
		}
	}

	return nil
}

// This wraps packet.LiteralData from the openpgp packet
// to conform the defined Plain interface
type OpenPgpPlain struct {
	ld packet.LiteralData
}

func (p *OpenPgpPlain) Body() io.Reader {
	return p.ld.Body
}

func (p *OpenPgpPlain) IsBinary() bool {
	return p.ld.IsBinary
}

func (p *OpenPgpPlain) FileName() string {
	return p.ld.FileName
}

type OpenPgPDecrypter struct {
	privateKeyRing openpgp.EntityList
	// TODO: move alreadyPromptedKeys into #Decrypt
	alreadyPromptedKeys map[[20]byte]struct{}
	promptFunction      openpgp.PromptFunction
}

func NewOpenPgPDecrypter(privateKeyRing openpgp.EntityList, promptFunction openpgp.PromptFunction) Decrypter {
	d := &OpenPgPDecrypter{}
	d.privateKeyRing = privateKeyRing
	d.alreadyPromptedKeys = make(map[[20]byte]struct{})
	if promptFunction != nil {
		d.promptFunction = promptFunction
	} else {
		d.promptFunction = getBashPromptForPassword(d)
	}
	return d
}

func (d *OpenPgPDecrypter) Decrypt(reader io.Reader) (plain Plain, err error) {
	pgpBlock, err := armor.Decode(reader)
	if err != nil {
		return nil, err
	}
	md, err := openpgp.ReadMessage(pgpBlock.Body, d.privateKeyRing, d.promptFunction, nil)
	if err != nil {
		return nil, err
	}
	return &OpenPgpPlain{*md.LiteralData}, nil
}

func (d *OpenPgPDecrypter) CanDecrypt(reader io.Reader) (bool, io.Reader) {
	readBytes, err := ioutil.ReadAll(reader)
	if err != nil {
		panic(err)
	}
	readerToReturn := bytes.NewReader(readBytes)
	readerToTest := bytes.NewReader(readBytes)
	_, err = armor.Decode(readerToTest)
	if err != nil {
		return false, readerToReturn
	}
	return true, readerToReturn
}

func getBashPromptForPassword(d *OpenPgPDecrypter) openpgp.PromptFunction {
	f := func(keys []openpgp.Key, symmetric bool) (password []byte, err error) {
		for _, key := range keys {
			if _, ok := d.alreadyPromptedKeys[key.PublicKey.Fingerprint]; !ok {
				fmt.Printf("Please insert password for key with id '%X': ", key.PublicKey.KeyId)
				fmt.Scanln(&password)
				d.alreadyPromptedKeys[key.PublicKey.Fingerprint] = struct{}{}
				key.PrivateKey.Decrypt(password)
				return password, nil
			} else {
				continue
			}
		}
		return nil, openpgpErrors.ErrKeyIncorrect
	}
	return openpgp.PromptFunction(f)
}

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
