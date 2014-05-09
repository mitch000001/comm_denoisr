package crypto

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

var encrypter Encrypter

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
	encrypter = NewOpenPgPEncrypter(privring)
	decrypter = NewOpenPgPDecrypter(privring, openpgp.PromptFunction(func(keys []openpgp.Key, symmetric bool) (password []byte, err error) {
		if len(keys) > 0 {
			keys[0].PrivateKey.Decrypt([]byte("test1234"))
		}
		return []byte("test1234"), nil
	}))
}

func TestEncrypt(t *testing.T) {
	file, err := os.Open("../decrypted_message.txt")
	defer file.Close()
	if err != nil {
		panic(err)
	}
	plainBytes, err := ioutil.ReadAll(file)
	if err != nil {
		panic(err)
	}
	expectedMessage := string(plainBytes)
	encryptedMessage, err := encrypter.Encrypt(bytes.NewReader(plainBytes), "test1234")
	if err != nil {
		t.Fatal(err)
	}

	plain, err := decrypter.Decrypt(strings.NewReader(encryptedMessage))
	if err != nil {
		t.Fatal(err)
	}
	decryptedBytes, err := ioutil.ReadAll(plain.Body())
	if err != nil {
		t.Fatal(err)
	}

	decryptedMessage := string(decryptedBytes)
	if decryptedMessage != expectedMessage {
		t.Fatalf("expected %v to equal %v", decryptedMessage, expectedMessage)
	}
}

func TestEncryptFor(t *testing.T) {
	file, err := os.Open("../decrypted_message.txt")
	defer file.Close()
	if err != nil {
		panic(err)
	}
	plainBytes, err := ioutil.ReadAll(file)
	if err != nil {
		panic(err)
	}
	expectedMessage := string(plainBytes)
	encryptedMessage, err := encrypter.EncryptFor(bytes.NewReader(plainBytes), []string{"test@example.com"})
	if err != nil {
		t.Fatal(err)
	}

	plain, err := decrypter.Decrypt(strings.NewReader(encryptedMessage))
	if err != nil {
		t.Fatal(err)
	}
	decryptedBytes, err := ioutil.ReadAll(plain.Body())
	if err != nil {
		t.Fatal(err)
	}

	decryptedMessage := string(decryptedBytes)
	if decryptedMessage != expectedMessage {
		t.Fatalf("expected %v to equal %v", decryptedMessage, expectedMessage)
	}
}
