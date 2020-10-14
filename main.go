package main

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

func checkErr(err error) {
	if err != nil {
		log.Fatalf("cause of err : %v", err)
	}
}

func main() {

	// Create a file in the desktop tpo store the
	// private and public keys.
	privateKey, publicKey := generateKeys()

	privPem := encodePrivKeyToPem(privateKey)
	pubPem := encodePubKeyToPem(&publicKey)

	fileName := "pem.txt"
	file, err := os.Create(fileName)

	checkErr(err)

	defer file.Close()

	err = ioutil.WriteFile(fileName, []byte(privPem), 0644)

	err = ioutil.WriteFile(fileName, []byte(pubPem), 0644)

	checkErr(err)

	// User input for message to be encrypted and signed.
	message := bufio.NewScanner(os.Stdin)
	fmt.Println("Please type your message: ")
	message.Scan()
	newMsg := message.Text()

	// Message encrypted..
	encryptedMsg, err := rsa.EncryptOAEP(sha256.New(), rand.Reader,
		&publicKey, []byte(newMsg), nil)

	if err != nil {
		panic(err)
	}
	fmt.Sprintln(encryptedMsg)

	// Signing a message with private key to produce
	// a signature and secure message.
	data := sha256.Sum256([]byte(newMsg))

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, data[:])
	checkErr(err)

	// Verify that message was signed with private key
	// belonging to held public key.
	err = rsa.VerifyPKCS1v15(&publicKey, crypto.SHA256, data[:], signature)
	checkErr(err)

	fmt.Println("Verification successful...")
}

// Generate private and public keys using rsa.Generate.
func generateKeys() (*rsa.PrivateKey, rsa.PublicKey) {

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
	}
	return privKey, privKey.PublicKey
}

func encodePrivKeyToPem(key *rsa.PrivateKey) string {
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "Rsa private key",
			Bytes: keyBytes,
		},
	)
	return string(keyPem)
}
func encodePubKeyToPem(key *rsa.PublicKey) string {
	keyBytes := x509.MarshalPKCS1PublicKey(key)
	keyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "Rsa public key",
			Bytes: keyBytes,
		},
	)
	return string(keyPem)
}
