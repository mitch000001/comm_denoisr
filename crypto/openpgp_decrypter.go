package crypto

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"code.google.com/p/go.crypto/openpgp/errors"
	"code.google.com/p/go.crypto/openpgp/packet"
	"fmt"
	"io"
	"io/ioutil"
)

// This wraps packet.LiteralData from the openpgp packet
// to conform the defined Plain interface
type OpenPgpPlain struct {
	ld packet.LiteralData
}

func (p *OpenPgpPlain) Body() io.Reader {
	return p.ld.Body
}

func (p *OpenPgpPlain) IsBinary() bool {
	return p.ld.IsBinary
}

func (p *OpenPgpPlain) FileName() string {
	return p.ld.FileName
}

type OpenPgPDecrypter struct {
	privateKeyRing openpgp.EntityList
	// TODO: move alreadyPromptedKeys into #Decrypt
	alreadyPromptedKeys map[[20]byte]struct{}
	promptFunction      openpgp.PromptFunction
}

func NewOpenPgPDecrypter(privateKeyRing openpgp.EntityList, promptFunction openpgp.PromptFunction) Decrypter {
	d := &OpenPgPDecrypter{}
	d.privateKeyRing = privateKeyRing
	d.alreadyPromptedKeys = make(map[[20]byte]struct{})
	if promptFunction != nil {
		d.promptFunction = promptFunction
	} else {
		d.promptFunction = getBashPromptForPassword(d)
	}
	return d
}

func (d *OpenPgPDecrypter) Decrypt(reader io.Reader) (plain Plain, err error) {
	pgpBlock, err := armor.Decode(reader)
	if err != nil {
		return nil, err
	}
	md, err := openpgp.ReadMessage(pgpBlock.Body, d.privateKeyRing, d.promptFunction, nil)
	if err != nil {
		return nil, err
	}
	return &OpenPgpPlain{*md.LiteralData}, nil
}

func (d *OpenPgPDecrypter) CanDecrypt(reader io.Reader) (bool, io.Reader) {
	readBytes, err := ioutil.ReadAll(reader)
	if err != nil {
		panic(err)
	}
	readerToReturn := bytes.NewReader(readBytes)
	readerToTest := bytes.NewReader(readBytes)
	_, err = armor.Decode(readerToTest)
	if err != nil {
		return false, readerToReturn
	}
	return true, readerToReturn
}

func getBashPromptForPassword(d *OpenPgPDecrypter) openpgp.PromptFunction {
	f := func(keys []openpgp.Key, symmetric bool) (password []byte, err error) {
		for _, key := range keys {
			if _, ok := d.alreadyPromptedKeys[key.PublicKey.Fingerprint]; !ok {
				fmt.Printf("Please insert password for key with id '%X': ", key.PublicKey.KeyId)
				fmt.Scanln(&password)
				d.alreadyPromptedKeys[key.PublicKey.Fingerprint] = struct{}{}
				key.PrivateKey.Decrypt(password)
				return password, nil
			} else {
				continue
			}
		}
		return nil, errors.ErrKeyIncorrect
	}
	return openpgp.PromptFunction(f)
}