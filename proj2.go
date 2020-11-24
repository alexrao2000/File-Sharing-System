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
	"strconv"

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
	K_password []byte
	K_private userlib.PKEDecKey
	K_DS_private userlib.DSSignKey
	AES_key_storage_keys map[string]uuid.UUID

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// The structure definition for an encrypted volume
type Volume struct {
	Ciphertext []byte // 2^30B + 16B of IV
	MAC []byte
	N_pad uint32 // number of pads
}

// The structure definition for a set of a file AES key & its Digital Signature
type SignedKey struct {
	PKE_k_file []byte
	DS_k_file []byte
}

// HELPERS start here

// Return storage keys of public PKE & DS keys, K_PUBKEY & K_DSKEY as strings,
// for user with USERNAME
func StorageKeysPublicKey(username string) (string, string) {
	byte_pub := []byte(username + "public_key")
	byte_DS := []byte(username + "DS_key")
	hash_pub := userlib.Hash(byte_pub)
	hash_DS := userlib.Hash(byte_DS)
	k_pubkey, _ := uuid.FromBytes(hash_pub[:16])
	k_DSkey, _ := uuid.FromBytes(hash_DS[:16])
	return k_pubkey.String(), k_DSkey.String()
}

// Store the User struct at USERDATAPRT, with K_PASSWORD to generate keys
func StoreUser(userdataptr *User, k_password []byte) (err error) {
	const k_password_len uint32 = 16
	// Encoding
	user_struct, _ := json.Marshal(userdataptr)
	//userlib.DebugMsg("DEBUG: user JSON %s\n", string(bytes))

	// Encode salt
	salt_encrypt := []byte("user_encrypt")
	//userlib.DebugMsg("DEBUG: user JSON %s\n", string(salt_encrypt))
	salt_auth := []byte("user_auth")
	//userlib.DebugMsg("DEBUG: user JSON %s\n", string(salt_auth))
	salt_storage := []byte("user_storage")
	//userlib.DebugMsg("DEBUG: user JSON %s\n", string(salt_storage))

	//HKDF
	k_user_encrypt, err := userlib.HashKDF(k_password, salt_encrypt)
	if err != nil {
		return err
	}
	k_user_encrypt = k_user_encrypt[:k_password_len]

	k_user_auth, err := userlib.HashKDF(k_password, salt_auth)
	if err != nil {
		return err
	}
	k_user_auth = k_user_auth[:k_password_len]

	k_user_storage, err := userlib.HashKDF(k_password, salt_storage)
	if err != nil {
		return err
	}
	k_user_storage = k_user_storage[:k_password_len]

	byte_username := []byte(userdataptr.Username)
	hmac_username, err := userlib.HashKDF(k_user_storage, byte_username)
	hmac_username = hmac_username[:k_password_len]
	if err != nil {
		return err
	}
	ID_user, err := uuid.FromBytes(hmac_username)
	if err != nil {
		return err
	}

	// Encryption

	iv := userlib.RandomBytes(userlib.AESBlockSize)

	// Padding
	pad_len := (len(user_struct) / 16 + 1) * 16
	//userlib.DebugMsg("size: %v", len(user_struct))
	padded_struct := Pad(user_struct, len(user_struct), pad_len)

	cyphertext_user := userlib.SymEnc(k_user_encrypt, iv, padded_struct)
	hmac_cyphertext, err := userlib.HashKDF(k_user_auth, cyphertext_user)
	if err != nil {
		return err
	}
	hmac_cpt := append(hmac_cyphertext, cyphertext_user...)
	//userlib.DebugMsg("size: %v, %v, %v", len(hmac_cyphertext), len(cyphertext_user), len(hmac_cpt))
	userlib.DatastoreSet(ID_user, hmac_cpt)

	return nil
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
	last_val := len(slice) - pad_len
	return slice[:last_val]
}

/*
//Returns true if two byte slices are equal, false otherwise
func bytesEqual(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }
    for i, v := range a {
        if v != b[i] {
            return false
        }
    }
    return true
}
*/

// This handles panics and should print the error
func HandlePanics()  {
	if recovery := recover(); recovery != nil {
		userlib.DebugMsg("DO NOT PANIC:", recovery)
	}
}

func GetAESKeys(ID_k uuid.UUID, userdata *User) ([]byte, error) {

	m_keys, ok := userlib.DatastoreGet(ID_k)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not found!"))
	}

	signed_keys := make(map[string]SignedKey)
	json.Unmarshal(m_keys, signed_keys)
	signed_key := signed_keys[userdata.Username]

	_, k_DSkey := StorageKeysPublicKey(userdata.Username)
	k_DS_pub, ok := userlib.KeystoreGet(k_DSkey)
	if !ok {
		return nil, errors.New(strings.ToTitle("No DS key found!"))
	}
	err := userlib.DSVerify(k_DS_pub, signed_key.PKE_k_file, signed_key.DS_k_file)
	if err != nil {
		return nil, err
	}

	pke_k_file := signed_key.PKE_k_file
	k_file_front_padded, err := userlib.PKEDec(userdata.K_private, pke_k_file)
	if err != nil {
		return nil, err
	}

	k_file := k_file_front_padded[16:]
	return k_file, nil

}

func StoreAESKeys(ID_k uuid.UUID, k_file []byte, userdata *User, recipient string) error {

	m_keys, ok := userlib.DatastoreGet(ID_k)
	if !ok {
		return errors.New(strings.ToTitle("No marshalled keys found!"))
	}

	//Obtain user's sign key and recipient's public key
	k_pubkey, _ := StorageKeysPublicKey(recipient)
	k_pub, ok := userlib.KeystoreGet(k_pubkey)
	if !ok {
		return errors.New(strings.ToTitle("k_pub not found in Keystore!"))
	}
	k_DS_private := userdata.K_DS_private

	//Sign and Encrypt
	enc_k_file, err := userlib.PKEEnc(k_pub, k_file)
	if err != nil {
		return err
	}
	signed_k_file, err := userlib.DSSign(k_DS_private, enc_k_file)
	if err != nil {
		return err
	}

	//Create SignedKey
	var signed_key SignedKey
	signed_key.PKE_k_file = enc_k_file
	signed_key.DS_k_file = signed_k_file
	signed_keys := make(map[string]SignedKey)
	json.Unmarshal(m_keys, signed_keys)
	signed_keys[recipient] = signed_key //recipient or userdata?
	m_keys, _ = json.Marshal(signed_keys)
	userlib.DatastoreSet(ID_k, m_keys)

	return err

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

	// Key generation
	byte_username := []byte(username)
	byte_password := []byte(password)

	//userlib.DebugMsg("DEBUG: key gen %s\n", string(byte_username))

	k_password := userlib.Argon2Key(byte_password, byte_username, k_password_len)

	// Store user data
	userdata.Username = username
	userdata.AES_key_storage_keys = make(map[string]uuid.UUID)
	userdata.K_password = k_password
	userdata.K_private = K_private
	userdata.K_DS_private = K_DS_private

	//store public keys
	k_pubkey, k_DSkey := StorageKeysPublicKey(username)
	userlib.KeystoreSet(k_pubkey, k_pub)
	userlib.KeystoreSet(k_DSkey, k_DS_pub)

	// Store User struct
	err = StoreUser(userdataptr, k_password)
	if err != nil {
		userlib.DebugMsg("Error: %v", err)
	}

	return userdataptr, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	const HMAC_size uint32 = 64
	const k_password_len uint32 = 16

	var userdata User
	userdataptr = &userdata

	salt_encrypt := []byte("user_encrypt")
	//userlib.DebugMsg("DEBUG: user JSON %s\n", string(salt_encrypt))
	salt_auth := []byte("user_auth")
	//userlib.DebugMsg("DEBUG: user JSON %s\n", string(salt_auth))
	salt_storage := []byte("user_storage")
	//userlib.DebugMsg("DEBUG: user JSON %s\n", string(salt_storage))

	// Key generation
	byte_username := []byte(username)
	byte_password := []byte(password)

	//userlib.DebugMsg("DEBUG: key gen %s\n", string(byte_username))

	k_password := userlib.Argon2Key(byte_password, byte_username, k_password_len)

	//HKDF
	k_user_encrypt, err := userlib.HashKDF(k_password, salt_encrypt)
	if err != nil {
		return nil, err
	}
	k_user_encrypt = k_user_encrypt[:k_password_len]

	k_user_auth, err := userlib.HashKDF(k_password, salt_auth)
	if err != nil {
		return nil, err
	}
	k_user_auth = k_user_auth[:k_password_len]

	k_user_storage, err := userlib.HashKDF(k_password, salt_storage)
	if err != nil {
		return nil, err
	}
	k_user_storage = k_user_storage[:k_password_len]

	//Calculate ID_sure
	hmac_username, err := userlib.HashKDF(k_user_storage, byte_username)
	if err != nil {
		return nil, err
	}
	hmac_username = hmac_username[:k_password_len]

	ID_user, err := uuid.FromBytes(hmac_username)
	if err != nil {
		return nil, err
	}

	existing_user, ok := userlib.DatastoreGet(ID_user)
	if ok != true {
		err = errors.New("User does not exist")
		return nil, err
	}

	//Decryption
	eu_cyphertext := existing_user[HMAC_size:]
	eu_plaintext := userlib.SymDec(k_user_encrypt, eu_cyphertext)
	stored_hmac := existing_user[:HMAC_size]
	//userlib.DebugMsg("size: %v, %v, %v", len(stored_hmac), len(eu_cyphertext), len(existing_user))
	evaluated_hmac, err := userlib.HashKDF(k_user_auth, eu_cyphertext)
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(stored_hmac, evaluated_hmac) {
		err = errors.New("Invalid user credentials")
		return nil, err
	}
	depadded_user := Depad(eu_plaintext)
	//userlib.DebugMsg("size: %v", len(depadded_user))
	json.Unmarshal(depadded_user, userdataptr)

	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	// Parameter
	const VOLUME_SIZE = 1048576 // 2^20 bytes
	const k_password_len uint32 = 16
	const ENCRYPTED_VOLUME_SIZE = 1048576 /*VOLUME_SIZE*/ + 16 /*userlib.AESBlockSize*/
	// userlib.DebugMsg("VOLUME_SIZE mod AES block size is %v", VOLUME_SIZE % userlib.AESBlockSize)

	// Encoding
	packaged_data, _ := json.Marshal(data)

	// Splitting
	data_size := len(packaged_data) // bytes
	n_volumes := data_size / VOLUME_SIZE + 1
	volumes := make([][]byte, n_volumes)
	volumes_encrypted := make([]Volume, n_volumes)
	for i := 0; i <= n_volumes - 2; i++ {
		index_starting := i * VOLUME_SIZE
		volumes[i] = packaged_data[index_starting : index_starting+VOLUME_SIZE]
		volumes_encrypted[i].N_pad = 0
	}
	// Check if last volume has remainder data
	remainder_data_size := data_size % VOLUME_SIZE
	var last_volume []byte
	if remainder_data_size != 0 {
		copy(last_volume[:], packaged_data[(n_volumes - 1) * VOLUME_SIZE:])
	}
	Pad(last_volume[:], remainder_data_size, VOLUME_SIZE)
	volumes_encrypted[n_volumes - 1].N_pad = uint32(VOLUME_SIZE - remainder_data_size)
	volumes[n_volumes - 1] = last_volume
	// Encryption & authentication
	k_file := userlib.RandomBytes(int(k_password_len))
	iv := make([]byte, userlib.AESBlockSize)
	// var k_volume [k_password_len]byte
	for index, volume := range volumes {
		index_string := strconv.Itoa(index)
		// Encrypt
		iv = userlib.RandomBytes(userlib.AESBlockSize)
		salt_volume_encryption := []byte("volume_encryption" + index_string)
		salt_volume_authentication := []byte("volume_authentication" + index_string)
		k_volume, err := userlib.HashKDF(k_file,
			salt_volume_encryption)
		if err != nil {
			userlib.DebugMsg("%v", err)
			return
		}
		k_volume = k_volume[:k_password_len]
		defer HandlePanics()
		volumes_encrypted[index].Ciphertext = userlib.SymEnc(k_volume, iv, volume)
		// Authentication
		k_volume_MAC, err := userlib.HashKDF(k_file,
			salt_volume_authentication)
		if err != nil {
			userlib.DebugMsg("%v", err)
			return
		}
		k_volume_MAC = k_volume_MAC[:k_password_len]
		volumes_encrypted[index].MAC, err = userlib.HMACEval(k_volume_MAC, volumes_encrypted[index].Ciphertext)
		if err != nil {
			userlib.DebugMsg("%v", err)
			return
		}
	}
	// Fetch public keys
	k_pubkey, _ := StorageKeysPublicKey(userdata.Username)
	k_pub, ok := userlib.KeystoreGet(k_pubkey)
	if !ok {
		userlib.DebugMsg("%v", errors.New(strings.ToTitle("Public key fetch failed")))
		return
	}

	// PKE & Publish AES key
	k_file_front_padded := make([]byte, k_password_len * 2)
	copy(k_file_front_padded[:k_password_len], userlib.RandomBytes(int(k_password_len)))
	copy(k_file_front_padded[k_password_len:], k_file)
	pke_k_file, err := userlib.PKEEnc(k_pub, k_file_front_padded)
	if err != nil {
		userlib.DebugMsg("%v", err)
		return
	}
	ds_k_file, err := userlib.DSSign(userdata.K_DS_private, pke_k_file)
	if err != nil {
		userlib.DebugMsg("%v", err)
		return
	}
	ID_k := uuid.New()
	userdata.AES_key_storage_keys[filename] = ID_k
	// userdata.AES_key_indices[filename] = 0
	var signed_key SignedKey
	signed_key.PKE_k_file = pke_k_file
	signed_key.DS_k_file = ds_k_file
	signed_keys := make(map[string]SignedKey)
	signed_keys[userdata.Username] = signed_key
	StoreUser(userdata, userdata.K_password)
	signed_keys_marshal, _ := json.Marshal(signed_keys)
	userlib.DatastoreSet(ID_k, signed_keys_marshal)

	// Store data
	stored, _ := json.Marshal(volumes_encrypted)
	hash_ID_k := userlib.Hash([]byte(ID_k.String()))
	ID_file, err := uuid.FromBytes(hash_ID_k[:16])
	if err != nil {
		userlib.DebugMsg("%v", err)
		return
	}
	userlib.DatastoreSet(ID_file, stored)
	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	// Find UUID of keys
	// index_k = userdata.AES_key_indices[filename]
	// ID_k := userdata.AES_key_storage_keys[filename]
	// userlib.DatastoreSet(k_ID, append(ds_k_file, pke_k_file))
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
	const k_password_len uint32 = 16

	//Retrieve k_file
	ID_k := userdata.AES_key_storage_keys[filename]
	k_file, err := GetAESKeys(ID_k, userdata)
	if err != nil {
		return "", errors.New(strings.ToTitle("File not found!"))
	}

	//Retrieve k_pub
	k_pubkey, _ := StorageKeysPublicKey(recipient)
	k_pub, ok := userlib.KeystoreGet(k_pubkey)
	if !ok {
		return "", errors.New(strings.ToTitle("k_pub not found in Keystore!"))
	}
	k_DS_private := userdata.K_DS_private

	//Create SignedKey
	StoreAESKeys(ID_k, k_file, userdata, recipient)
	StoreUser(userdata, userdata.K_password)

	//Generate token
	bytes_ID_k, err := json.Marshal(ID_k)
	if err != nil {
		return "", err
	}
	enc_ID_k, err := userlib.PKEEnc(k_pub, bytes_ID_k)
	if err != nil {
		return "", errors.New(strings.ToTitle("File not found!"))
	}
	signed_ID_k, err := userlib.DSSign(k_DS_private, enc_ID_k)
	if err != nil {
		return "", errors.New(strings.ToTitle("File not found!"))
	}

	var token SignedKey
	token.PKE_k_file = enc_ID_k
	token.DS_k_file = signed_ID_k
	bytes_token, err := json.Marshal(token)
	if err != nil {
		return "", err
	}

	magic_string = hex.EncodeToString(bytes_token)

	return magic_string, err
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {

	//Retrieve keys
	_, k_DSkey := StorageKeysPublicKey(sender)
	k_DS_pub, ok := userlib.KeystoreGet(k_DSkey)
	if !ok {
		return errors.New(strings.ToTitle("File not received!"))
	}
	k_private := userdata.K_private

	//Verify and Decrypt
	var token SignedKey
	var ID_k uuid.UUID

	bytes_token := []byte(magic_string)
	err := json.Unmarshal(bytes_token, token)
	if err != nil {
		return err
	}
	err = userlib.DSVerify(k_DS_pub, token.PKE_k_file, token.DS_k_file)
	if err != nil {
		return err
	}
	bytes_ID_k, err := userlib.PKEDec(k_private, token.PKE_k_file)
	if err != nil {
		return err
	}
	err = json.Unmarshal(bytes_ID_k, ID_k)
	if err != nil {
		return err
	}

	//Add new file to map
	k_file, err := GetAESKeys(ID_k, userdata)
	if err != nil {
		return err
	}

	StoreAESKeys(ID_k, k_file, userdata, userdata.Username)
	StoreUser(userdata, userdata.K_password)

	return err
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	return
}
