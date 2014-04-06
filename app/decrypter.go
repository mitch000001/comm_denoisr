package decrypter

import (
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"code.google.com/p/go.crypto/openpgp/errors"
	"fmt"
	"io/ioutil"
	"os"
)

type Decrypter struct {
	privateKeyRing      openpgp.KeyRing
	alreadyPromptedKeys map[[20]byte]struct{}
}

func NewDecrypter(privateKeyRing openpgp.KeyRing) *Decrypter {
	d := new(Decrypter)
	d.privateKeyRing = privateKeyRing
	d.alreadyPromptedKeys = make(map[[20]byte]struct{})
	return d
}

func (d *Decrypter) DecryptMessage(file *os.File) (message string, err error) {
	pgpBlock, err := armor.Decode(file)
	if err != nil {
		return "", err
	}
	md, err := openpgp.ReadMessage(pgpBlock.Body, d.privateKeyRing, openpgp.PromptFunction(d.promptForPassword), nil)
	if err != nil {
		return "", err
	}
	messageBody, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	return string(messageBody), nil
}

func (d *Decrypter) promptForPassword(keys []openpgp.Key, symmetric bool) (password []byte, err error) {
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
	return nil, errors.ErrKeyIncorrect
}
