// Synthetic Go snippet for detector tests
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
)

func main() {
	key, _ := rsa.GenerateKey(rand, 2048)
	_, _ = ecdsa.GenerateKey(elliptic.P256(), rand)
}
