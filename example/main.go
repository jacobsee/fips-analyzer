package main

import (
	"crypto/sha256"
	"fmt"
	"log"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

func main() {
	// FIPS approved algorithms
	approvedHash()
	approvedKDF()

	// Non-FIPS approved algorithms
	nonApprovedHash()
	nonApprovedCipher()
	nonApprovedKDF()

	// Unknown x/crypto package
	unknownCrypto()
}

// Examples using FIPS approved algorithms
func approvedHash() {
	// Standard library SHA-256 (FIPS approved)
	data := []byte("test data")
	hash := sha256.Sum256(data)
	fmt.Printf("SHA-256: %x\n", hash)

	// SHA-3 from x/crypto (FIPS approved)
	sha3Hash := sha3.Sum256(data)
	fmt.Printf("SHA-3-256: %x\n", sha3Hash)
}

func approvedKDF() {
	// PBKDF2 (FIPS approved)
	password := []byte("password")
	salt := []byte("salt")
	key := pbkdf2.Key(password, salt, 4096, 32, sha256.New)
	fmt.Printf("PBKDF2 key: %x\n", key)
}

// Examples using non-FIPS approved algorithms
func nonApprovedHash() {
	// BLAKE2b (not FIPS approved)
	data := []byte("test data")
	hash, err := blake2b.New256(nil)
	if err != nil {
		log.Fatal(err)
	}
	hash.Write(data)
	result := hash.Sum(nil)
	fmt.Printf("BLAKE2b-256: %x\n", result)
}

func nonApprovedCipher() {
	// ChaCha20-Poly1305 (not FIPS approved)
	key := make([]byte, 32)
	_, err := chacha20poly1305.New(key)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("ChaCha20-Poly1305 cipher created")
}

func nonApprovedKDF() {
	// scrypt (not FIPS approved)
	password := []byte("password")
	salt := []byte("salt")
	key, err := scrypt.Key(password, salt, 32768, 8, 1, 32)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("scrypt key: %x\n", key)
}

func unknownCrypto() {
	// NaCl box (not in the known packages list)
	publicKey := make([]byte, 32)
	privateKey := make([]byte, 32)
	nonce := make([]byte, 24)
	message := []byte("test message")

	encrypted := box.Seal(nil, message, (*[24]byte)(nonce), (*[32]byte)(publicKey), (*[32]byte)(privateKey))
	fmt.Printf("NaCl box encrypted: %x\n", encrypted)
}
