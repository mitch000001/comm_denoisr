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
	privateKeyRing openpgp.KeyRing
}

func NewDecrypter(privateKeyRing openpgp.KeyRing) *Decrypter {
	d := new(Decrypter)
	d.privateKeyRing = privateKeyRing
	return d
}

func (decrypter *Decrypter) DecryptMessage(file *os.File) (message string, err error) {
	pgpBlock, err := armor.Decode(file)
	if err != nil {
		return "", err
	}
	if alreadyPromptedKeys != nil {
		alreadyPromptedKeys = nil
	}
	md, err := openpgp.ReadMessage(pgpBlock.Body, decrypter.privateKeyRing, openpgp.PromptFunction(promptForPassword), nil)
	if err != nil {
		return "", err
	}
	messageBody, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	return string(messageBody), nil
}

var alreadyPromptedKeys map[[20]byte]struct{}

func promptForPassword(keys []openpgp.Key, symmetric bool) (password []byte, err error) {
	if alreadyPromptedKeys == nil {
		alreadyPromptedKeys = make(map[[20]byte]struct{})
	}
	for _, key := range keys {
		if _, ok := alreadyPromptedKeys[key.PublicKey.Fingerprint]; !ok {
			fmt.Printf("Please insert password for key with id '%X': ", key.PublicKey.KeyId)
			fmt.Scanln(&password)
			alreadyPromptedKeys[key.PublicKey.Fingerprint] = struct{}{}
			key.PrivateKey.Decrypt(password)
			return password, nil
		} else {
			continue
		}
	}
	return nil, errors.ErrKeyIncorrect
}
