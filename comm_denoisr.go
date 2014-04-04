package main

import (
	. "./app"
	"code.google.com/p/go.crypto/openpgp"
	"fmt"
	"github.com/codegangsta/cli"
	"log"
	"os"
)

var app *cli.App
var denoisr *Denoisr

func init() {
	app = cli.NewApp()
	app.Name = "comm_denoisr"
	app.Usage = "Denoise your communication"
	app.Version = "0.0.1"
	app.Flags = []cli.Flag{
		cli.StringFlag{Name: "input, i", Usage: "Set filename here"},
	}
	decryptCommand := cli.Command{
		Name:        "decrypt",
		ShortName:   "d",
		Usage:       "decrypt file",
		Description: "Decrypt files provided",
		Action:      decrypt,
	}
	app.Commands = []cli.Command{
		decryptCommand,
	}
}

func main() {
	privringFile, err := os.Open("test_keyring.gpg")
	if err != nil {
		log.Fatalln(err)
	}
	privring, err := openpgp.ReadKeyRing(privringFile)
	if err != nil {
		privring, err = openpgp.ReadArmoredKeyRing(privringFile)
		if err != nil {
			log.Fatalln(err)
		}
	}
	denoisr = NewDenoisr(privring)
	if false {
		var private_email string
		var myPrivateKey *openpgp.Entity
		for myPrivateKey == nil {
			if len(private_email) != 0 {
				fmt.Printf("No key found for email address '%v'. Try again? (y/n)", private_email)
				var again string
				_, err := fmt.Scanln(&again)
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
				_, err := fmt.Scanln(&private_email)
				if err != nil {
					log.Fatalln(err)
				}
				myPrivateKey = getKeyByEmail(privring, private_email)
			}
		}
		fmt.Println(myPrivateKey)
	}
	app.Run(os.Args)
}

func decrypt(c *cli.Context) {
	input := c.Args().First()
	if input == "" {
		cli.ShowCommandHelp(c, "decrypt")
	} else {
		file, err := os.Open(input)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println(denoisr.DecryptMessage(file))
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
