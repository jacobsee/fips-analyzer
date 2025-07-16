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

	// Import the cryptoinit module - this will trigger init() functions
	"example/cryptoinit"
)

func main() {
	// FIPS approved algorithms
	approvedHash()
	approvedKDF()

	// Non-FIPS approved algorithms
	nonApprovedCipher()
	nonApprovedKDF()

	// Unknown x/crypto package
	unknownCrypto()

	// Demonstrate usage of the crypto operations in init() functions
	demonstrateInitCrypto()

	// NEW: Demonstrate crypto usage through interfaces
	demonstrateInterfaceCrypto()
}

// demonstrateInitCrypto shows usage of crypto in init functions
func demonstrateInitCrypto() {
	cryptoinit.EncryptData([]byte("Hello, FIPS!"))
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

func demonstrateInterfaceCrypto() {
	data := []byte("interface test data")

	sha3Hasher := &SHA3Hasher{}
	blake2bHasher := &Blake2bHasher{}

	GenericHashProcessor(data, sha3Hasher)
	GenericHashProcessor(data, blake2bHasher)

	fmt.Println("Hashes processed through interfaces")
}

// Test whether calls to crypto functions through interfaces are detected

type CryptoHasher interface {
	HashData(data []byte) []byte
	GetName() string
}

type SHA3Hasher struct{}

func (h *SHA3Hasher) HashData(data []byte) []byte {
	hash := sha3.Sum256(data)
	return hash[:]
}

func (h *SHA3Hasher) GetName() string {
	return "SHA-3-256"
}

type Blake2bHasher struct{}

func (h *Blake2bHasher) HashData(data []byte) []byte {
	hasher, err := blake2b.New256(nil)
	if err != nil {
		log.Fatal(err)
	}
	hasher.Write(data)
	return hasher.Sum(nil)
}

func (h *Blake2bHasher) GetName() string {
	return "BLAKE2b-256"
}

func GenericHashProcessor(data []byte, hasher CryptoHasher) {
	result := hasher.HashData(data)
	fmt.Printf("%s (via interface): %x\n", hasher.GetName(), result)
}
