// Package to compute HMAC-SHA256 digests for input strings
//
// used to prove simplicity of generating HMAC-SHA256, performance and comparison operations

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"time"
)

// Define type to allow interface implementation against string
type data string

// HMAC related functions, compute hmac and compare to provided value
type hmacsha256Computation interface {
	compute(key string) []byte
	compare(key string, generated []byte) bool
}

// Main entry point
func main() {
	defer timeTrack(time.Now(), "Hashing")
	inputStrings := os.Args[1:]
	key := inputStrings[0]
	for _, s := range inputStrings[1:] {
		obj := data(s)
		hash := obj.compute(key)
		verified := obj.compare(key, hash)
		fmt.Printf("INPUT: %s, HMAC-SHA256: %s, Verified: %t\n",
			string(obj),
			base64.StdEncoding.EncodeToString(hash),
			verified)
	}
}

// Compute SHA256 on the Data Object
func (d *data) compute(key string) []byte {
	message := []byte(*d)
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(message)
	return mac.Sum(nil)
}

// Compare a provided hash digest to a newly generated hash against the provided data object.
func (d *data) compare(key string, generated []byte) bool {
	currentHash := d.compute(key)
	return hmac.Equal(currentHash, generated)
}

// Track the time it took to execute the process.
func timeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	fmt.Printf("%s took %s", name, elapsed)
}
