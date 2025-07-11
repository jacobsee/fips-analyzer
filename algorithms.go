package main

// PackageStatus represents the FIPS status of an entire package
type PackageStatus struct {
	FIPSStatus string `json:"fips_status"`
}

var knownPackages = map[string]PackageStatus{
	// FIPS Approved packages
	"golang.org/x/crypto/sha3": {
		FIPSStatus: "approved",
	},
	"golang.org/x/crypto/pbkdf2": {
		FIPSStatus: "approved",
	},
	"golang.org/x/crypto/hkdf": {
		FIPSStatus: "approved",
	},
	"golang.org/x/crypto/xts": {
		FIPSStatus: "approved",
	},

	// Must evaluate manually
	"golang.org/x/crypto/scrypt": {
		FIPSStatus: "must_evaluate_manually",
	},
	"golang.org/x/crypto/ed25519": {
		FIPSStatus: "must_evaluate_manually",
	},

	// Rejected packages
	"golang.org/x/crypto/blake2b": {
		FIPSStatus: "rejected",
	},
	"golang.org/x/crypto/blake2s": {
		FIPSStatus: "rejected",
	},
	"golang.org/x/crypto/md4": {
		FIPSStatus: "rejected",
	},
	"golang.org/x/crypto/ripemd160": {
		FIPSStatus: "rejected",
	},
	"golang.org/x/crypto/chacha20": {
		FIPSStatus: "rejected",
	},
	"golang.org/x/crypto/chacha20poly1305": {
		FIPSStatus: "rejected",
	},
	"golang.org/x/crypto/poly1305": {
		FIPSStatus: "rejected",
	},
	"golang.org/x/crypto/salsa20": {
		FIPSStatus: "rejected",
	},
	"golang.org/x/crypto/tea": {
		FIPSStatus: "rejected",
	},
	"golang.org/x/crypto/xtea": {
		FIPSStatus: "rejected",
	},
	"golang.org/x/crypto/twofish": {
		FIPSStatus: "rejected",
	},
	"golang.org/x/crypto/blowfish": {
		FIPSStatus: "rejected",
	},
	"golang.org/x/crypto/cast5": {
		FIPSStatus: "rejected",
	},
	"golang.org/x/crypto/bcrypt": {
		FIPSStatus: "rejected",
	},
	"golang.org/x/crypto/argon2": {
		FIPSStatus: "rejected",
	},
	"golang.org/x/crypto/curve25519": {
		FIPSStatus: "rejected",
	},
	"golang.org/x/crypto/otr": {
		FIPSStatus: "rejected",
	},
	"golang.org/x/crypto/bn256": {
		FIPSStatus: "rejected",
	},
}
