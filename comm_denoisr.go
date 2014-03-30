package main

import (
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"code.google.com/p/go.crypto/openpgp/errors"
	"fmt"
	"log"
	"os"
)

func main() {
	homeDir := os.Getenv("HOME")
	privringFile, err := os.Open(homeDir + "/.gnupg/secring.gpg")
	if err != nil {
		log.Fatalln(err)
	}
	privring, _ := openpgp.ReadKeyRing(privringFile)
	var private_email string
	var myPrivateKey *openpgp.Entity
	for myPrivateKey == nil {
		if len(private_email) != 0 {
			fmt.Printf("No key found for email address '%v'. Try again? (y/n)", private_email)
			var again string
			_, err := fmt.Scan(&again)
			if err != nil {
				log.Fatalln(err)
			}
			if again != "y" {
				return
			} else {
				private_email = ""
				continue
			}
		} else {
			fmt.Println("Insert the email for your private key")
			_, err := fmt.Scan(&private_email)
			if err != nil {
				log.Fatalln(err)
			}
			myPrivateKey = getKeyByEmail(privring, private_email)
		}
	}
	fmt.Println(myPrivateKey)
	decryptionKeys := privring.DecryptionKeys()
	for _, key := range decryptionKeys {
		fmt.Printf("Found decryption key with id %X\n", key.PublicKey.KeyId)
	}

	args := os.Args[1:]
	if len(args) > 0 {
		file, err := os.Open(args[0])
		if err != nil {
			log.Fatalln(err)
		}
		pgpBlock, err := armor.Decode(file)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println(pgpBlock.Type)
		if alreadyPromptedKeys != nil {
			alreadyPromptedKeys = nil
		}
		md, err := openpgp.ReadMessage(pgpBlock.Body, privring, openpgp.PromptFunction(promptForPassword), nil)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println(md)
	}
}

func getKeyByEmail(keyring openpgp.EntityList, email string) *openpgp.Entity {
	for _, entity := range keyring {
		for _, ident := range entity.Identities {
			if ident.UserId.Email == email {
				return entity
			}
		}
	}

	return nil
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
