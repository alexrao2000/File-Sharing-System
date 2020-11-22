package proj2

// CS 161 Project 2 Fall 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
    var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username string
	K_private userlib.PKEDecKey
	K_DS_private userlib.DSSignKey

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// Return storage keys of public PKE & DS keys, K_PUBKEY & K_DSKEY as strings,
// for user with USERNAME
func StorageKeysPublicKey(username string) (string, string) {
	byte_pub, err := hex.DecodeString(username + "public_key")
	if err != nil {
		return "", ""
	}
	byte_DS, err := hex.DecodeString(username + "DS_key")
	if err != nil {
		return "", ""
	}
	hash_pub := userlib.Hash(byte_pub)
	hash_DS := userlib.Hash(byte_DS)
	k_pubkey, _ := uuid.FromBytes(hash_pub[:16])
	k_DSkey, _ := uuid.FromBytes(hash_DS[:16])
	return k_pubkey.String(), k_DSkey.String()
}

// Pad SLICE according to the PKCS #7 scheme,
// i.e. padding with the number (as a byte) of elements to pad,
// from PRESENT_LENGTH to TARGET_LENGTH
// Do nothing if TARGET_LENGTH is no longer than PRESENT_LENGTH is
func Pad(slice []byte, present_length int, target_length int) []byte {
	pad := target_length - present_length
	if pad > 0 && len(slice) <= target_length {
		pad_byte := byte(pad % 256)
		for j := present_length; j < target_length; j++ {
			slice = append(slice, pad_byte)
		}
	}
	return slice
}

//Depad a padded byte array, ex. user_struct
func Depad(slice []byte) []byte {
	pad_len := int(slice[len(slice)-1])
	last_val := len(slice) - (pad_len + 1)
	return slice[:last_val]
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing
// hashes of common passwords downloaded from the internet.
func InitUser(username string, password string) (userdataptr *User, err error) {
	const k_password_len uint32 = 16

	var userdata User
	userdataptr = &userdata

	//Adding private keys
	k_pub, K_private, _ := userlib.PKEKeyGen()
	//userlib.DebugMsg("Key is %v, %v", k_pub, K_private)

	K_DS_private, k_DS_pub, _ := userlib.DSKeyGen()
	//userlib.DebugMsg("Key is %v, %v", k_DS_pub, K_DS_private)

	//store private keys
	userdata.K_private = K_private
	userdata.K_DS_private = K_DS_private

	//store public keys
	k_pubkey, k_DSkey := StorageKeysPublicKey(username)
	userlib.KeystoreSet(k_pubkey, k_pub)
	userlib.KeystoreSet(k_DSkey, k_DS_pub)

	//set username
	userdata.Username = username

	// Encoding
	user_struct, _ := json.Marshal(userdataptr)
	//userlib.DebugMsg("DEBUG: user JSON %s\n", string(bytes))

	salt_encrypt, _ := json.Marshal("user_encrypt")
	//userlib.DebugMsg("DEBUG: user JSON %s\n", string(salt_encrypt))
	salt_auth, _ := json.Marshal("user_auth")
	//userlib.DebugMsg("DEBUG: user JSON %s\n", string(salt_auth))
	salt_storage, _ := json.Marshal("user_storage")
	//userlib.DebugMsg("DEBUG: user JSON %s\n", string(salt_storage))

	// Key generation
	byte_username := []byte(username)
	byte_password := []byte(password)

	//userlib.DebugMsg("DEBUG: key gen %s\n", string(byte_username))

	k_password := userlib.Argon2Key(byte_password, byte_username, k_password_len)

	//HKDF
	k_user_encrypt, err := userlib.HashKDF(k_password, salt_encrypt)
	k_user_encrypt = k_user_encrypt[:k_password_len]
	if err != nil {
		return nil, err
	}
	k_user_auth, err := userlib.HashKDF(k_password, salt_auth)
	k_user_auth = k_user_auth[:k_password_len]
	if err != nil {
		return nil, err
	}
	k_user_storage, err := userlib.HashKDF(k_password, salt_storage)
	k_user_storage = k_user_storage[:k_password_len]
	if err != nil {
		return nil, err
	}

	hmac_username, err := userlib.HashKDF(k_user_storage, byte_username)
	hmac_username = hmac_username[:k_password_len]
	if err != nil {
		return nil, err
	}
	ID_user, err := uuid.FromBytes(hmac_username)
	if err != nil {
		return nil, err
	}

	// Encryption

	iv := userlib.RandomBytes(userlib.AESBlockSize)

	// Padding
	pad_len := (len(user_struct) / 16 + 1) * 16
	padded_struct := Pad(user_struct, len(user_struct), pad_len)

	cyphertext_user := userlib.SymEnc(k_user_encrypt, iv, padded_struct)
	hmac_cyphertext, err := userlib.HashKDF(k_user_auth, cyphertext_user)
	if err != nil {
		return nil, err
	}
	hmac_cpt := append(hmac_cyphertext, cyphertext_user...)
	userlib.DatastoreSet(ID_user, hmac_cpt)

	return userdataptr, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	const k_password_len uint32 = 16

	var userdata User
	userdataptr = &userdata

	//Adding private keys
	_, K_private, _ := userlib.PKEKeyGen()
	//userlib.DebugMsg("Key is %v, %v", k_pub, K_private)

	K_DS_private, _, _ := userlib.DSKeyGen()
	//userlib.DebugMsg("Key is %v, %v", k_DS_pub, K_DS_private)

	//store private keys
	userdata.K_private = K_private
	userdata.K_DS_private = K_DS_private

	//store public keys
	//k_pubkey, k_DSkey := StorageKeysPublicKey(username)
	//userlib.KeystoreSet(k_pubkey, k_pub)
	//userlib.KeystoreSet(k_DSkey, k_DS_pub)

	//set username
	userdata.Username = username

	// Encoding
	user_struct, _ := json.Marshal(userdataptr)
	//userlib.DebugMsg("DEBUG: user JSON %s\n", string(bytes))

	salt_encrypt, _ := json.Marshal("user_encrypt")
	//userlib.DebugMsg("DEBUG: user JSON %s\n", string(salt_encrypt))
	salt_auth, _ := json.Marshal("user_auth")
	//userlib.DebugMsg("DEBUG: user JSON %s\n", string(salt_auth))
	salt_storage, _ := json.Marshal("user_storage")
	//userlib.DebugMsg("DEBUG: user JSON %s\n", string(salt_storage))

	// Key generation
	byte_username := []byte(username)
	byte_password := []byte(password)

	//userlib.DebugMsg("DEBUG: key gen %s\n", string(byte_username))

	k_password := userlib.Argon2Key(byte_password, byte_username, k_password_len)

	//HKDF
	k_user_encrypt, err := userlib.HashKDF(k_password, salt_encrypt)
	k_user_encrypt = k_user_encrypt[:k_password_len]
	if err != nil {
		return nil, err
	}
	k_user_auth, err := userlib.HashKDF(k_password, salt_auth)
	k_user_auth = k_user_auth[:k_password_len]
	if err != nil {
		return nil, err
	}
	k_user_storage, err := userlib.HashKDF(k_password, salt_storage)
	k_user_storage = k_user_storage[:k_password_len]
	if err != nil {
		return nil, err
	}

	hmac_username, err := userlib.HashKDF(k_user_storage, byte_username)
	hmac_username = hmac_username[:k_password_len]
	if err != nil {
		return nil, err
	}
	ID_user, err := uuid.FromBytes(hmac_username)
	if err != nil {
		return nil, err
	}

	// Encryption
	iv := userlib.RandomBytes(userlib.AESBlockSize)

	// Padding
	pad_len := (len(user_struct) / 16 + 1) * 16
	padded_struct := Pad(user_struct, len(user_struct), pad_len)

	cyphertext_user := userlib.SymEnc(k_user_encrypt, iv, padded_struct)
	hmac_cyphertext, err := userlib.HashKDF(k_user_auth, cyphertext_user)
	if err != nil {
		return nil, err
	}
	hmac_cpt := append(hmac_cyphertext, cyphertext_user...)
	existing_user, ok := userlib.DatastoreGet(ID_user)
	if ok != true {
		err = errors.New("User does not exist")
		return nil, err
	}
	if userlib.HMACEqual(hmac_cpt, existing_user) {
		err = errors.New("Invalid user credentials")
		return nil, err
	}

	//Depad
	userdata = Depad(existing_user)

	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

	//TODO: This is a toy implementation.
	UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	packaged_data, _ := json.Marshal(data)
	userlib.DatastoreSet(UUID, packaged_data)
	//End of toy implementation

	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	//TODO: This is a toy implementation.
	UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	packaged_data, ok := userlib.DatastoreGet(UUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not found!"))
	}
	json.Unmarshal(packaged_data, &data)
	return data, nil
	//End of toy implementation

	return
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	return
}
