package main

// This file tests behaviour of Go & userlib funcs

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"

	"fmt"

	// // Life is much easier with json:  You are
	// // going to want to use this so you can easily
	// // turn complex structures into strings etc...
	// "encoding/json"
	//
	// // Likewise useful for debugging, etc...
	// "encoding/hex"
	//
	// // UUIDs are generated right based on the cryptographic PRNG
	// // so lets make life easier and use those too...
	// //
	// // You need to add with "go get github.com/google/uuid"
	// "github.com/google/uuid"
	//
	// // Useful for debug messages, or string manipulation for datastore keys.
	// "strings"
	//
	// // Want to import errors.
	// "errors"
	//
	// // Optional. You can remove the "_" there, but please do not touch
	// // anything else within the import bracket.
	// "strconv"
	// // if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// // see someUsefulThings() below:
)

func main() {
    plaintext := []byte("This is a test")
	plaintext = append(plaintext, 2, 2)
    fmt.Println("Length of plaintext", len(plaintext))
    k := userlib.RandomBytes(16)
    iv := userlib.RandomBytes(userlib.AESBlockSize)
    fmt.Println("Length of ciphertext is %v", len(userlib.SymEnc(k, iv, plaintext)))

	sign_key, verify_key, _ = userlib.DSKeyGen()
	
}
