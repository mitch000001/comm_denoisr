package crypto

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func readPrivateKeyRing() openpgp.EntityList {
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
	return privring
}

func createDecryptionPrompt() openpgp.PromptFunction {
	promptFunction := openpgp.PromptFunction(func(keys []openpgp.Key, symmetric bool) (password []byte, err error) {
		if len(keys) > 0 {
			keys[0].PrivateKey.Decrypt([]byte("test1234"))
		}
		return []byte("test1234"), nil
	})
	return promptFunction
}

func TestEncrypt(t *testing.T) {
	decrypter := NewOpenPgPDecrypter(readPrivateKeyRing(), createDecryptionPrompt())
	encrypter := NewOpenPgPEncrypter(readPrivateKeyRing())
	file, err := os.Open("../fixtures/decrypted_message.txt")
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
	decrypter := NewOpenPgPDecrypter(readPrivateKeyRing(), createDecryptionPrompt())
	encrypter := NewOpenPgPEncrypter(readPrivateKeyRing())
	file, err := os.Open("../fixtures/decrypted_message.txt")
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
		t.Fatalf("expected %v to equal %v\n", decryptedMessage, expectedMessage)
	}
}

func TestEncryptForHidden(t *testing.T) {
	privring := readPrivateKeyRing()
	promptFunction := createDecryptionPrompt()
	encrypter := NewOpenPgPEncrypter(privring)
	file, err := os.Open("../fixtures/decrypted_message.txt")
	defer file.Close()
	if err != nil {
		panic(err)
	}
	plainBytes, err := ioutil.ReadAll(file)
	if err != nil {
		panic(err)
	}
	expectedMessage := string(plainBytes)
	encryptedMessage, err := encrypter.EncryptForHidden(bytes.NewReader(plainBytes), []string{"test@example.com"})
	if err != nil {
		t.Fatal(err)
	}

	pgpBlock, err := armor.Decode(strings.NewReader(encryptedMessage))
	if err != nil {
		t.Fatal(err)
	}

	md, err := openpgp.ReadMessage(pgpBlock.Body, privring, promptFunction, nil)
	if err != nil {
		t.Fatal(err)
	}

	encryptedToKeyId := md.EncryptedToKeyIds[0]
	if encryptedToKeyId != uint64(0) {
		t.Fatalf("expected encryptedToKeyId to equal 0, got %X\n", encryptedToKeyId)
	}

	for _, entity := range privring {
		for _, s := range entity.Subkeys {
			if s.PublicKey.KeyId == uint64(0) {
				t.Fatalf("expected KeyId from subkey with fingerprint %v not to equal 0\n", s.PublicKey.Fingerprint)
			}
		}
	}

	decryptedBytes, err := ioutil.ReadAll(md.LiteralData.Body)
	if err != nil {
		t.Fatal(err)
	}

	decryptedMessage := string(decryptedBytes)
	if decryptedMessage != expectedMessage {
		t.Fatalf("expected %v to equal %v\n", decryptedMessage, expectedMessage)
	}

}

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

func TestCanDecrypt(t *testing.T) {
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

	canDecrypt, _ := decrypter.CanDecrypt(file)

	if !canDecrypt {
		t.Fatalf("expected CanDecrypt to return true, got false")
	}

}
