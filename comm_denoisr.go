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
		decryptedMessage := denoisr.DecryptMessage(file)
		if filename := c.String("output"); filename != "" {
			err := ioutil.WriteFile(filename, []byte(decryptedMessage), os.FileMode(0007))
			if err != nil {
				log.Fatalln(err)
			}
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
