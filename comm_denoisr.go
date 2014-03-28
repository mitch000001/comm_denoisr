package main

import (
	"code.google.com/p/go.crypto/openpgp"
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

	args := os.Args[1:]
	if len(args) > 0 {
		file, err := os.Open(args[0])
		if err != nil {
			log.Fatalln(err)
		}
		md, err := openpgp.ReadMessage(file, privring, nil, nil)
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
