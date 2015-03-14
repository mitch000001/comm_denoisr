package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/codegangsta/cli"
	"github.com/mitch000001/comm_denoisr/crypto"
	"golang.org/x/crypto/openpgp"
)

var configPath string = os.Getenv("HOME") + "/.comm_denoisr.conf"

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

var GnupgPrivateKeyringPath string = filepath.Join(os.Getenv("HOME"), ".gnupg", "secring.gpg")
var GnupgPublicKeyringPath string = filepath.Join(os.Getenv("HOME"), ".gnupg", "pubring.gpg")

type Config struct {
	GnupgPrivateKeyringPath string
	GnupgPublicKeyringPath  string
}

func main() {
	config, err := readConfig()
	check(err)
	privateKeyringPath := &config.GnupgPrivateKeyringPath
	if *privateKeyringPath == "" {
		*privateKeyringPath = promptPrivateKeyRingPath()
	}
	privring, err := OpenPrivateKeyRing(*privateKeyringPath)
	check(err)
	publicKeyringPath := &config.GnupgPublicKeyringPath
	if *publicKeyringPath == "" {
		*publicKeyringPath = promptPublicKeyRingPath()
	}
	pubring, err := OpenPublicKeyRing(*publicKeyringPath)
	check(err)
	defer func() {
		err := writeConfig(config)
		check(err)
	}()
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

func readConfig() (*Config, error) {
	var config Config
	file, err := os.OpenFile(configPath, os.O_RDONLY, 0666)
	if os.IsNotExist(err) {
		fmt.Println("Config does not exist")
		return &config, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	dec := json.NewDecoder(file)
	err = dec.Decode(&config)
	if err != nil {
		return nil, errors.New("Malformed config file!")
	}
	return &config, nil
}

func writeConfig(config *Config) error {
	file, err := os.OpenFile(configPath, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		fmt.Printf("Error %+#v: %s\n", err, err.Error())
		return err
	}
	defer file.Close()
	enc := json.NewEncoder(file)
	err = enc.Encode(config)
	if err != nil {
		return err
	}
	return nil
}

func promptPrivateKeyRingPath() string {
	var keyRingPath string
	fmt.Printf("Please enter the path to your private keyring [%v]: ", GnupgPrivateKeyringPath)
	fmt.Scanln(&keyRingPath)
	if keyRingPath == "" {
		keyRingPath = GnupgPrivateKeyringPath
	}
	return keyRingPath
}

func promptPublicKeyRingPath() string {
	var keyRingPath string
	fmt.Printf("Please enter the path to your public keyring [%v]: ", GnupgPublicKeyringPath)
	fmt.Scanln(&keyRingPath)
	if keyRingPath == "" {
		keyRingPath = GnupgPublicKeyringPath
	}
	return keyRingPath
}

func OpenPrivateKeyRing(keyRingPath string) (openpgp.EntityList, error) {
	fmt.Printf("Using '%s' as privateKeyring file\n", keyRingPath)
	return OpenKeyRing(keyRingPath)
}

func OpenPublicKeyRing(keyRingPath string) (openpgp.EntityList, error) {
	fmt.Printf("Using '%s' as publicKeyring file\n", keyRingPath)
	return OpenKeyRing(keyRingPath)
}

func OpenKeyRing(keyRingPath string) (openpgp.EntityList, error) {
	keyRingFile, err := os.Open(keyRingPath)
	defer keyRingFile.Close()
	if err != nil {
		return nil, err
	}
	keyRing, err := openpgp.ReadKeyRing(keyRingFile)
	if err != nil {
		keyRing, err = openpgp.ReadArmoredKeyRing(keyRingFile)
		if err != nil {
			return nil, err
		}
	}
	return keyRing, nil
}

func check(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
