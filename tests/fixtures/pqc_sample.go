// Fixture for PQC-ready detection: Open Quantum Safe liboqs-go (Kyber, Dilithium)
package main

import (
	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func main() {
	kem := oqs.KeyEncapsulation{}
	defer kem.Free()
	_ = kem.Init("Kyber512", nil)
}
