package main

import (
	. "./app"
	"code.google.com/p/go.crypto/openpgp"
	"fmt"
	"github.com/codegangsta/cli"
	"io/ioutil"
	"log"
	"os"
)

var app *cli.App
var decrypter *Decrypter

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
		Flags: []cli.Flag{
			cli.StringFlag{Name: "output, o", Usage: "-output filename"},
		},
		Action: decrypt,
	}
	app.Commands = []cli.Command{
		decryptCommand,
	}
}

func main() {
	privringFile, err := os.Open("test_keyring.gpg")
	check(err)
	privring, err := openpgp.ReadKeyRing(privringFile)
	if err != nil {
		privring, err = openpgp.ReadArmoredKeyRing(privringFile)
		check(err)
	}
	decrypter = NewDecrypter(privring)
	app.Run(os.Args)
}

func decrypt(c *cli.Context) {
	input := c.Args().First()
	if input == "" {
		cli.ShowCommandHelp(c, "decrypt")
	} else {
		file, err := os.Open(input)
		check(err)
		decryptedMessage, err := decrypter.DecryptMessage(file)
		check(err)
		if filename := c.String("output"); filename != "" {
			err := ioutil.WriteFile(filename, []byte(decryptedMessage), 0770)
			check(err)
		} else {
			fmt.Println(decryptedMessage)
		}
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

func check(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
