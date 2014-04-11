package decrypter

import (
	"code.google.com/p/go.crypto/openpgp"
	"io/ioutil"
	"os"
	"testing"
)

var decrypter *Decrypter

func init() {
	privringFile, err := os.Open("../test_keyring.gpg")
	if err != nil {
		panic(err)
	}
	privring, err := openpgp.ReadKeyRing(privringFile)
	if err != nil {
		privring, err = openpgp.ReadArmoredKeyRing(privringFile)
		if err != nil {
			panic(err)
		}
	}
	decrypter = NewDecrypter(privring, openpgp.PromptFunction(func(keys []openpgp.Key, symmetric bool) (password []byte, err error) {
		keys[0].PrivateKey.Decrypt([]byte("test1234"))
		return nil, nil
	}))
}

func TestDecryptMessage(t *testing.T) {
	file, err := os.Open("../encrypted_message_hidden_4E201F3E.txt")
	if err != nil {
		panic(err)
	}
	decryptedBytes, err := ioutil.ReadFile("../decrypted_message.txt")
	if err != nil {
		panic(err)
	}
	expectedMessage := string(decryptedBytes)
	decryptedMessage, err := decrypter.DecryptMessage(file)
	if err != nil {
		t.Fatal(err)
	}
	if decryptedMessage != expectedMessage {
		t.Fatalf("expected %v to equal %v", decryptedMessage, expectedMessage)
	}
}
