package crypto

import (
	"code.google.com/p/go.crypto/openpgp"
	"io/ioutil"
	"os"
	"testing"
)

func TestDecrypt(t *testing.T) {
	privringFile, err := os.Open("../fixtures/test_keyring.gpg")
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
	decrypter := NewOpenPgPDecrypter(privring, openpgp.PromptFunction(func(keys []openpgp.Key, symmetric bool) (password []byte, err error) {
		keys[0].PrivateKey.Decrypt([]byte("test1234"))
		return nil, nil
	}))

	file, err := os.Open("../fixtures/encrypted_message_hidden_4E201F3E.txt")
	if err != nil {
		panic(err)
	}
	decryptedBytes, err := ioutil.ReadFile("../fixtures/decrypted_message.txt")
	if err != nil {
		panic(err)
	}
	expectedMessage := string(decryptedBytes)
	plain, err := decrypter.Decrypt(file)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := ioutil.ReadAll(plain.Body())
	if err != nil {
		t.Fatal(err)
	}
	decryptedMessage := string(decrypted)
	if decryptedMessage != expectedMessage {
		t.Fatalf("expected %v to equal %v", decryptedMessage, expectedMessage)
	}
}
