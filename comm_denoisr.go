package main

import (
	"code.google.com/p/go.crypto/openpgp"
	"fmt"
	"github.com/codegangsta/cli"
	"github.com/mitch000001/comm_denoisr/crypto"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

var app *cli.App
var cryptoStrategy crypto.CryptoStrategy

func init() {
	app = cli.NewApp()
	app.Name = "comm_denoisr"
	app.Usage = "Denoise your communication"
	app.Version = "0.1.0"
	app.Flags = []cli.Flag{
		cli.StringFlag{Name: "input, i", Usage: "Set filename here"},
	}
	app.Commands = []cli.Command{
		cli.Command{
			Name:        "decrypt",
			ShortName:   "d",
			Usage:       "decrypt encrypted_file.txt",
			Description: "Decrypt files provided",
			Flags: []cli.Flag{
				cli.StringFlag{Name: "output, o", Usage: "--output filename"},
			},
			Action: decrypt,
		},
		cli.Command{
			Name:        "encrypt",
			ShortName:   "e",
			Usage:       "encrypt plaintext_file.txt",
			Description: "Encrypt files provided",
			Flags: []cli.Flag{
				cli.StringFlag{Name: "output, o", Usage: "--output filename"},
				cli.BoolFlag{Name: "hidden-recipient, R", Usage: "--hidden-recipient"},
			},
			Action: encrypt,
		},
	}
}

var GnupgPrivateKeyring string = os.Getenv("HOME") + "/.gnupg/secring.gpg"
var GnupgPublicKeyring string = os.Getenv("HOME") + "/.gnupg/pubring.gpg"

func main() {
	fmt.Printf("Please enter the path to your private keyring [%v]: ", GnupgPrivateKeyring)
	var privateKeyring string
	fmt.Scanln(&privateKeyring)
	if privateKeyring == "" {
		privateKeyring = GnupgPrivateKeyring
	}
	fmt.Printf("Using '%v' as privateKeyring file\n", privateKeyring)
	privringFile, err := os.Open(privateKeyring)
	defer privringFile.Close()
	check(err)
	privring, err := openpgp.ReadKeyRing(privringFile)
	if err != nil {
		privring, err = openpgp.ReadArmoredKeyRing(privringFile)
		check(err)
	}
	fmt.Printf("Please enter the path to your public keyring [%v]: ", GnupgPublicKeyring)
	var publicKeyring string
	fmt.Scanln(&publicKeyring)
	if publicKeyring == "" {
		publicKeyring = GnupgPublicKeyring
	}
	fmt.Printf("Using '%v' as publicKeyring file\n", publicKeyring)
	pubringFile, err := os.Open(publicKeyring)
	defer pubringFile.Close()
	check(err)
	pubring, err := openpgp.ReadKeyRing(pubringFile)
	if err != nil {
		pubring, err = openpgp.ReadArmoredKeyRing(pubringFile)
		check(err)
	}
	cryptoStrategy = crypto.NewOpenPgpCryptoStrategy(pubring, privring, nil)
	app.Run(os.Args)
}

func decrypt(c *cli.Context) {
	input := c.Args().First()
	if input == "" {
		cli.ShowCommandHelp(c, "decrypt")
	} else {
		file, err := os.Open(input)
		defer file.Close()
		check(err)
		encrypted, err := cryptoStrategy.Read(file)
		check(err)
		plain, err := cryptoStrategy.Decrypt(encrypted)
		check(err)
		decryptedBytes, err := ioutil.ReadAll(plain.Body())
		check(err)
		if filename := c.String("output"); filename != "" {
			err := ioutil.WriteFile(filename, []byte(decryptedBytes), 0770)
			check(err)
		} else {
			fmt.Println(string(decryptedBytes))
		}
	}
}

func encrypt(c *cli.Context) {
	input := c.Args().First()
	if input == "" {
		cli.ShowCommandHelp(c, "encrypt")
	} else {
		file, err := os.Open(input)
		defer file.Close()
		check(err)
		// TODO: ask the user for an email, maybe present options from keyring
		fmt.Print("Enter the emails to which the message should be encrypted, separated by spaces: ")
		var emails string
		fmt.Scanln(&emails)
		recipients := strings.Split(emails, " ")
		fmt.Printf("Message will be encrypted to the following recipients: %v\n", recipients)
		encryptHidden := c.Bool("hidden-recipient")
		var encryptedMessage string
		if encryptHidden {
			encryptedMessage, err = cryptoStrategy.EncryptForHidden(file, recipients)
		} else {
			encryptedMessage, err = cryptoStrategy.EncryptFor(file, recipients)
		}
		check(err)
		if filename := c.String("output"); filename != "" {
			err := ioutil.WriteFile(filename, []byte(encryptedMessage), 0770)
			check(err)
		} else {
			fmt.Println(encryptedMessage)
		}
	}
}

func check(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
