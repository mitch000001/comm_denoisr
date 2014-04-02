package denoisr

import (
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"code.google.com/p/go.crypto/openpgp/errors"
	"fmt"
	"log"
	"os"
)

type Denoisr struct {
	privateKeyRing openpgp.KeyRing
}

func NewDenoisr(privateKeyRing openpgp.KeyRing) *Denoisr {
	d := new(Denoisr)
	d.privateKeyRing = privateKeyRing
	return d
}

func (denoisr *Denoisr) DecryptMessage(file *os.File) (message string) {
	pgpBlock, err := armor.Decode(file)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(pgpBlock.Type)
	if alreadyPromptedKeys != nil {
		alreadyPromptedKeys = nil
	}
	md, err := openpgp.ReadMessage(pgpBlock.Body, denoisr.privateKeyRing, openpgp.PromptFunction(promptForPassword), nil)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(md)
	return ""
}

var alreadyPromptedKeys map[[20]byte]struct{}

func promptForPassword(keys []openpgp.Key, symmetric bool) (password []byte, err error) {
	if alreadyPromptedKeys == nil {
		alreadyPromptedKeys = make(map[[20]byte]struct{})
	}
	fmt.Printf("Keys: %v (%v)\n", len(keys)-len(alreadyPromptedKeys), keys)
	for _, key := range keys {
		if _, ok := alreadyPromptedKeys[key.PublicKey.Fingerprint]; !ok {
			fmt.Printf("Please insert password for key with id '%X'\n", key.PublicKey.KeyId)
			fmt.Scan(&password)
			fmt.Printf("Password: %v", string(password))
			alreadyPromptedKeys[key.PublicKey.Fingerprint] = struct{}{}
			return password, nil
		} else {
			continue
		}
	}
	return nil, errors.ErrKeyIncorrect
}
