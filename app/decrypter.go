package decrypter

import (
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"code.google.com/p/go.crypto/openpgp/errors"
	"fmt"
	"io"
	"io/ioutil"
)

type Decrypter struct {
	privateKeyRing      openpgp.KeyRing
	alreadyPromptedKeys map[[20]byte]struct{}
	promptFunction      openpgp.PromptFunction
}

func NewDecrypter(privateKeyRing openpgp.KeyRing, promptFunction openpgp.PromptFunction) *Decrypter {
	d := new(Decrypter)
	d.privateKeyRing = privateKeyRing
	d.alreadyPromptedKeys = make(map[[20]byte]struct{})
	if promptFunction != nil {
		d.promptFunction = promptFunction
	} else {
		d.promptFunction = getBashPromptForPassword(d)
	}
	return d
}

func (d *Decrypter) DecryptMessage(reader io.Reader) (message string, err error) {
	pgpBlock, err := armor.Decode(reader)
	if err != nil {
		return "", err
	}
	md, err := openpgp.ReadMessage(pgpBlock.Body, d.privateKeyRing, d.promptFunction, nil)
	if err != nil {
		return "", err
	}
	messageBody, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}
	return string(messageBody), nil
}

func getBashPromptForPassword(d *Decrypter) openpgp.PromptFunction {
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
		return nil, errors.ErrKeyIncorrect
	}
	return openpgp.PromptFunction(f)
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
