package main

import "C"
import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// Global variable
var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey

//export Init
func Init(num_bits int) int {
	// The GenerateKey method takes in a reader that returns random bits, and
	// the number of bits
	privateKey_temp, err := rsa.GenerateKey(rand.Reader, num_bits)
	if err != nil {
		return 1
	}
	privateKey = privateKey_temp
	publicKey = &privateKey_temp.PublicKey

	return 0
}

//export Display_PQ
func Display_PQ() {
	privateKey.Dump_PQ()
}

//export Victim
func Victim(CTBytes []byte) uint {
	_, err := rsa.DecryptOAEP(sha256.New(), nil, privateKey, CTBytes, rsa.OAEPOptions{}.Label)
	if err != nil {
		return 0
	} else {
		return 1
	}
}

func main() {

}
