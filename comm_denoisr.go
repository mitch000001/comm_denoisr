package main

import (
	"code.google.com/p/go.crypto/openpgp"
	"fmt"
	"github.com/codegangsta/cli"
	"github.com/mitch000001/comm_denoisr/crypto"
	"io/ioutil"
	"log"
	"os"
)

var app *cli.App
var d crypto.Decrypter
var e crypto.Encrypter

func init() {
	app = cli.NewApp()
	app.Name = "comm_denoisr"
	app.Usage = "Denoise your communication"
	app.Version = "0.1.0"
	app.Flags = []cli.Flag{
		cli.StringFlag{Name: "input, i", Usage: "Set filename here"},
	}
	decryptCommand := cli.Command{
		Name:        "decrypt",
		ShortName:   "d",
		Usage:       "decrypt encrypted_file.txt",
		Description: "Decrypt files provided",
		Flags: []cli.Flag{
			cli.StringFlag{Name: "output, o", Usage: "-output filename"},
		},
		Action: decrypt,
	}
	encryptCommand := cli.Command{
		Name:        "encrypt",
		ShortName:   "e",
		Usage:       "encrypt plaintext_file.txt",
		Description: "Encrypt files provided",
		Flags: []cli.Flag{
			cli.StringFlag{Name: "output, o", Usage: "-output filename"},
		},
		Action: encrypt,
	}
	app.Commands = []cli.Command{
		decryptCommand,
		encryptCommand,
	}
}

var GnupgPublicKeyring string = os.Getenv("HOME") + "/.gnupg/secring.gpg"

func main() {
	fmt.Printf("Please enter the path to your private keyring [%v]: ", GnupgPublicKeyring)
	var keyring string
	fmt.Scanln(&keyring)
	if keyring == "" {
		keyring = GnupgPublicKeyring
	}
	fmt.Printf("Using '%v' as keyring file\n", keyring)
	privringFile, err := os.Open(keyring)
	defer privringFile.Close()
	check(err)
	privring, err := openpgp.ReadKeyRing(privringFile)
	if err != nil {
		privring, err = openpgp.ReadArmoredKeyRing(privringFile)
		check(err)
	}
	d = crypto.NewOpenPgPDecrypter(privring, nil)
	e = crypto.NewOpenPgPEncrypter(privring)
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
		canDecrypt, reader := d.CanDecrypt(file)
		if !canDecrypt {
			log.Fatalln("Can not decrypt encrypted data provided")
		}
		plain, err := d.Decrypt(reader)
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
		emails := make([]string, 10)
		iSlice := make([]interface{}, len(emails))
		for i := range emails {
			iSlice[i] = &emails[i]
		}
		fmt.Scanln(iSlice...)
		recipients := make([]string, 0)
		for _, v := range emails {
			if v != "" {
				recipients = append(recipients, v)
			}
		}
		fmt.Printf("Message will be encrypted to the following recipients: %v\n", recipients)
		encryptedMessage, err := e.EncryptForHidden(file, recipients)
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
