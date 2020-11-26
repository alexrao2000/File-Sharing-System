package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"testing"
	"reflect"
	"github.com/cs161-staff/userlib"
	_ "encoding/json"
	_ "encoding/hex"
	_ "github.com/google/uuid"
	_ "strings"
	_ "errors"
	_ "strconv"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u1, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	//t.Log("Initialized user", u1)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
	u2, err := GetUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error(err)
		return
	}
	//t.Log("Got user", u2)
	if reflect.DeepEqual(u1, u2) {
		t.Log("User was initialized and got")
	}

	u3, err := InitUser("bob", "")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user with empty password", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	//t.Log("Initialized user", u1)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
	u3_0, err := GetUser("bob", "")
	if err != nil {
		// t.Error says the test fails
		t.Error(err)
		return
	}
	//t.Log("Got user", u2)
	if reflect.DeepEqual(u3, u3_0) {
		t.Log("User was initialized and got")
	}

	u4, err := GetUser("bob", "")
	if err != nil {
		// t.Error says the test fails
		t.Error(err)
		return
	}
	if reflect.DeepEqual(u3, u4) {
		t.Log("User was initialized and got")
	}

	_, err = InitUser("bob", "hey")
	if err == nil {
		// t.Error says the test fails
		t.Error("Should not be able to initialize two users with the same username")
		return
	}

	_, err = GetUser("bob", "hey")
	if err == nil {
		t.Error("User should not be able to log in with incorrect password")
		return
	}
}

func TestStorage(t *testing.T) {
	clear()
	u1, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	//Get two instances of the same user
	u1, err = GetUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error(err)
		return
	}
	u2, err := GetUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error(err)
		return
	}
	if reflect.DeepEqual(u1, u2) {
		t.Log("User was initialized and got")
	}

	//Store and load
	v := []byte("This is a test")
	u1.StoreFile("file1", v)

	v2, err2 := u1.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}

	//Overwrite file
	hi := []byte("hi")
	u1.StoreFile("file1", hi)

	v, err2 = u1.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, hi) {
		t.Error("Did not correctly overwrite file", v, hi)
		return
	}

	//Load file without access
	u2, err = InitUser("bob", "rabuf")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	_, err3 := u2.LoadFile("file1")
	if err3 == nil {
		t.Log("User loaded file to which they do not have access")
		return
	}

	//Different user, store same file name
	u2.StoreFile("file1", v)

	v, err2 = u2.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	v2, err2 = u1.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Failed to store file of the same name and data with different user", v, v2)
		return
	}

	//Store with two instances of the same user
	u1, err = GetUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error(err)
		return
	}
	u2, err = GetUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error(err)
		return
	}
	u1.StoreFile("file1", v)
	u2.StoreFile("file2", v2)
	v, err2 = u2.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed load file with two instances of same user", err2)
		return
	}
	v2, err2 = u1.LoadFile("file2")
	if err2 != nil {
		t.Error("Failed load file with two instances of same user", err2)
		return
	}

	// Empty filename
	u1.StoreFile("", v)

	v0, err2 := u1.LoadFile("")
	if err2 != nil {
		t.Error("Failed to upload and download empty filename", err2)
		return
	}
	if !reflect.DeepEqual(v, v0) {
		t.Error("Downloaded file is not the same if filename is empty", v, v2)
		return
	}

	// Empty file
	v1 := []byte("")
	u1.StoreFile("empty", v1)

	v1_1, err2 := u1.LoadFile("empty")
	if err2 != nil {
		t.Error("Failed to upload and download empty file", err2)
		return
	}
	if !reflect.DeepEqual(v1, v1_1) {
		t.Error("Downloaded empty file is not the same", v, v2)
		return
	}
}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u1, err := GetUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error(err)
		return
	}
	u2, err := GetUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error(err)
		return
	}
	if reflect.DeepEqual(u1, u2) {
		t.Log("User was initialized and got")
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file")
		return
	}
}

func TestShare(t *testing.T) {
	clear()
	u1, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u1, err = GetUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error(err)
		return
	}
	u2, err := GetUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error(err)
		return
	}
	if reflect.DeepEqual(u1, u2) {
		t.Log("User was initialized and got")
	}

	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}
	u3, err3 := InitUser("carl", "rabuf")
	if err3 != nil {
		t.Error("Failed to initialize bob", err3)
		return
	}

	v := []byte("This is a test")
	u1.StoreFile("file1", v)

	var v2 []byte
	var magic_string string

	v, err = u1.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u1.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	//Custom tests
	magic_string, err = u2.ShareFile("file1", "carl")
	if err == nil {
		t.Error("User should not share inaccessible filename", err)
		return
	}

	magic_string, err = u2.ShareFile("file2", "carl")
	if err != nil {
		t.Error("Cannot share shared file", err)
		return
	}

	err = u3.ReceiveFile("file3", "bob", magic_string)
	if err != nil {
		t.Error("Cannot receive tree-shared file", err)
		return
	}

	v = []byte("This is a test")
	// u3.StoreFile("file2", v)

	magic_string, err = u1.ShareFile("file1", "carl")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u3.ReceiveFile("file3", "alice", magic_string)
	if err == nil {
		t.Error("File with the same name already exists, but overwritten: ", err)
		return
	}

	magic_string, err = u1.ShareFile("file3", "carl")
	if err == nil {
		t.Error("Shared file that does not exist")
		return
	}

	//Revoke tests
	err = u1.RevokeFile("file3", "carl")
	if err == nil {
		t.Error("Revoked file should not exist", err)
		return
	}

	err = u1.RevokeFile("file1", "carl")
	if err == nil {
		t.Error("Target user is not a direct recipient")
		return
	}

	err = u1.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke file", err)
		return
	}

	_, err = u2.LoadFile("file2")
	if err == nil {
		t.Error("Revoked file still accessible", err)
		return
	}

	err = u2.AppendFile("file2", v)
	if err == nil {
		t.Error("Revoked file still modifiable", err)
		return
	}

	_, err = u2.ShareFile("file2", "carl")
	if err == nil {
		t.Error("Revoked file still shareable", err)
		return
	}

	_, err = u3.LoadFile("file3")
	if err == nil {
		t.Error("Tree-revoked file still accessible", err)
		return
	}

	err = u3.AppendFile("file3", v)
	if err == nil {
		t.Error("Tree-revoked file still modifiable", err)
		return
	}

	_, err = InitUser("delta", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err = u3.ShareFile("file3", "delta")
	if err == nil {
		t.Error("Tree-revoked file still shareable", err)
		return
	}
}

func TestAppend(t *testing.T) {
	clear()
	u1, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err := InitUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u1.StoreFile("file1", v)

	err = u1.AppendFile("file1", []byte("Append this string"))
	if err != nil {
		t.Error("Failed to append to file", err)
		return
	}

	v, err = u1.LoadFile("file1")
	if err != nil {
		t.Error("File failed to load", err)
		return
	}

	v_app := []byte("This is a testAppend this string")

	if !reflect.DeepEqual(v, v_app) {
		t.Error("Appending doesn't work", v, v_app)
		return
	}

	err = u1.AppendFile("file2", []byte("Append this string"))
	if err == nil {
		t.Error("User should not be able to append to file that does not exist")
		return
	}

	v = []byte("")
	u1.StoreFile("file2", v)

	err = u1.AppendFile("file2", []byte("Append this string"))
	if err != nil {
		t.Error("Cannot append to file that does not exist", err)
		return
	}

	err = u2.AppendFile("file2", []byte("Append this string"))
	if err == nil {
		t.Error("User should not be able to append to file to which they do not have access")
		return
	}

	var v2 []byte
	var magic_string string

	magic_string, err = u1.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	v, err = u1.LoadFile("file1")
	if err != nil {
		t.Error("File failed to load", err)
		return
	}
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	err = u2.AppendFile("file2", []byte("Append this string"))
	if err != nil {
		t.Error("Share did not grant access to user for append, something is wrong", err)
		return
	}

	err = u1.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke file", err)
		return
	}
	err = u2.AppendFile("file2", []byte("Append this string"))
	if err == nil {
		t.Error("User should have lost access and cannot append, something is wrong")
		return
	}
}
