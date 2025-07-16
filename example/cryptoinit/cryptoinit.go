package cryptoinit

import (
	"fmt"

	"golang.org/x/crypto/argon2"
)

func init() {
	fmt.Println("Running init-only crypto operations...")

	password := []byte("internal-setup-password")
	salt := []byte("internal-salt-12345678")

	// Note: Argon2 is not used anywhere in the main example module, only here in init
	internalKey := argon2.IDKey(password, salt, 1, 64*1024, 4, 32)

	fmt.Printf("Internal key derived during init using Argon2 (length: %d)\n", len(internalKey))
}

func EncryptData(plaintext []byte) []byte {
	// Perform nothing of substance here (notably, no direct x/crypto calls)
	// Merely including & using this will trigger the init function,
	// which DOES use x/crypto/argon2.
	return []byte{}
}
