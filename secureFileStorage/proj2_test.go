package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
	_ "github.com/google/uuid"
)

func TestCorruption(t *testing.T) {
	//user struct corruption
	InitUser("kubica", "2")
	data := userlib.DatastoreGetMap()
	var u_ userlib.UUID
	var prev []byte
	for key, val := range data {
		u_ = key
		userlib.DatastoreSet(key, userlib.RandomBytes(len(val)))
		prev = val

	}

	_, err := GetUser("kubica", "2")

	if err == nil {
		t.Error("Did not detect user corruption")
		return
	}
	userlib.DatastoreSet(u_, prev)

	//file struct corruption

	u, _ := GetUser("kubica", "2")

	u.StoreFile("williams", []byte("claire"))

	data = userlib.DatastoreGetMap()

	for key, val := range data {
		if key != u_ {
			userlib.DatastoreSet(key, userlib.RandomBytes(len(val)))
		}
	}

	_, err2 := u.LoadFile("williams")

	if err2 == nil {
		t.Error("Failed to detect file corruption")
		return
	}

	err3 := u.AppendFile("lotus", []byte("9"))

	if err3 == nil {
		t.Error("Appended non-existant file")
		return
	}

	_, err4 := u.ShareFile("lotus", "kubica" )
	if err4 == nil {
		t.Error("Attempted to share non-existant file")
		return
	}

	u.StoreFile("noice", []byte("l"))

	_, err4 = u.ShareFile("noice", "ham" )
	if err4 == nil {
		t.Error("Attempted to share with non-existant user")
		return
	}
}

func TestInit(t *testing.T) {
	t.Log("Initialization test")

	// You may want to turn it off someday
	userlib.SetDebugStatus(true)
	// someUsefulThings()  //  Don't call someUsefulThings() in the autograder in case a student removes it
	userlib.SetDebugStatus(false)
	u, err := InitUser("alice", "fubar")
	u2, err2 := InitUser("alice$!1", "1!s%A") //weird arguments
	u3, err3 := InitUser("", "")              //empty arguments
	u4, err4 := InitUser("eve", "fubar")      //same password
	if err != nil || err2 != nil || err3 != nil || err4 != nil {
		// t.Error says the test fails
		//t.Error("Failed to initialize user", err)
		t.Error("Failed to initialize one of the users")
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	//t.Log("Got user", u)
	_, _, _, _ = u, u2, u3, u4
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
}

func TestGetUser(t *testing.T) {
	_, err := GetUser("alice", "4bar")

	if err == nil {
		t.Error("Returned user with wrong password")
		return
	}

	u2, err1 := InitUser("ham", "44")

	if err1 != nil {
		t.Error("Init error : ", err1)
		return
	}

	u2.StoreFile("win", []byte("6th time champ"))

	u3, err2 := GetUser("ham", "44")

	if err2 != nil {
		t.Error("Failed to get user :", err2)
		return
	}

	eq := reflect.DeepEqual(u3, u2)

	if !eq {
		t.Error("User states are not equal")
		return
	}

}

func TestStorage(t *testing.T) {
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	u2, err2 := GetUser("alice$!1", "1!s%A")
	u3, err3 := GetUser("", "")

	if err != nil || err2 != nil || err3 != nil {
		t.Error("Failed to reload one of the users")
		return
	}

	//t.Log("Loaded user", u)
	_, _, _ = u, u2, u3

	v := []byte("This is a test")
	v2 := []byte("!@13sZ()")
	v3 := []byte("")

	u.StoreFile("file1", v)
	u2.StoreFile("@(#*)", v2)
	u3.StoreFile("", v3)

	d, dErr := u.LoadFile("file1")
	d2, dErr2 := u2.LoadFile("@(#*)")
	d3, dErr3 := u3.LoadFile("")
	d4, dErr4 := u.LoadFile("nonexistent")

	//Loading file that does not exist
	if d4 != nil || dErr4 == nil {
		t.Error("File should not exist")
		return
	}


	if dErr != nil || dErr2 != nil || dErr3 != nil {
		//t.Error("Failed to upload and download", dErr)
		t.Error("Failed to upload and download one of the files")
		return
	}

	//t.Log(v3, d3)
	//t.Log(v, d)
	//t.Log(reflect.DeepEqual([]byte(""), []byte("")))
	if !reflect.DeepEqual(v, d) || !reflect.DeepEqual(v2, d2) || !reflect.DeepEqual(v3, d3) {
		t.Error("Downloaded file is not the same", v3, d3)
		//t.Error("One or more of the downloaded files is not the same")
		return
	}
}

func TestAppend(t *testing.T) {
	u, _ := GetUser("alice", "fubar")
	u2, _ := GetUser("alice$!1", "1!s%A")
	u3, _ := GetUser("", "")

	e := u3.AppendFile("", []byte(":O "))
	e2 := u3.AppendFile("", []byte(":)"))
	if e != nil || e2 != nil {
		t.Error("Append error", e)
		return
	}
	d3, _ := u3.LoadFile("")
	if string(d3) != ":O :)" {
		t.Error("Incorrect append")
		return
	}

	e3 := u.AppendFile("", []byte(" :| "))
	if e3 == nil {
		t.Error("Should not be able to append file without access")
		return
	}


	magic_string, _ := u3.ShareFile("", "alice")
	magic_string2, _ := u3.ShareFile("", "alice$!1")
	u.ReceiveFile("jesus", "", magic_string)
	u2.ReceiveFile("", "", magic_string2)
	v, _ := u.LoadFile("jesus")
	v2, _ := u2.LoadFile("")
	v3, _ := u3.LoadFile("")

	if string(v) != string(v3) || string(v) != string(v2) {
		t.Error("Shared file is not equal")
		return
	}

	e4 := u.AppendFile("jesus", []byte(":|"))
	e5 := u2.AppendFile("", []byte("obama"))
	if e4 != nil || e5 != nil {
		t.Error("Problem with appending")
		return
	}

	v, _ = u.LoadFile("jesus")
	v2, _ = u2.LoadFile("")
	v3, _ = u3.LoadFile("")

	if string(v) != string(v3) || string(v) != string(v2) {
		t.Error("Shared file is not equal")
		return
	}

	u3.RevokeFile("", "alice")
	e6 := u.AppendFile("jesus", []byte("yes"))
	if e6 == nil {
		t.Error("Should not be able to append after revoked permission")
		return
	}

	u2.AppendFile("", []byte("gains"))

	v, _ = u.LoadFile("jesus")
	v2, _ = u2.LoadFile("")
	v3, _ = u3.LoadFile("")

	if string(v) == string(v3) {
		t.Error("Shared file should not be equal after append from revoked user")
		return
	}

	if string(v3) != string(v2) {
		t.Error("Shared file is not equal")
		return
	}


}

func TestShare(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	var v, v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
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

	u.StoreFile("file4", []byte("bottas"))

	m, _:= u.ShareFile("file4", "bob")

	err3 := u2.ReceiveFile("noice", "alice$!1", m)

	if err3 == nil {
		t.Error("Failed to verify user")
		return
	}
	u4, _ := GetUser("alice$!1", "1!s%A" )

	err4 := u4.ReceiveFile("gotti", "alice", m)

	if err4 == nil {
		t.Error("Unintended recipient able to use magic string")
		return
	}
}

func TestUser_RevokeFile(t *testing.T) {
	u, err := InitUser("alice5", "fubar1")

	u.StoreFile("file1", []byte("nn"))

	l2, e1 := u.LoadFile("file1")

	if e1 != nil {
		t.Error("Failed to load file: ", e1)
		return
	}

	err20 := u.RevokeFile("nn", "ham")

	if err20 == nil {
		t.Error("Revoked non-existant file")
		return
	}


	m_string, e := u.ShareFile("file1", "bob")
	if e != nil {
		t.Error("Failed to share with bob", e)
		return
	}

	if err != nil {
		t.Error("Failed to get user", err)
		return
	}

	u2, err2 := GetUser("eve", "fubar")

	if err2 != nil {
		t.Error("Failed to initialize user", err2)
		return
	}

	magic_string, err := u.ShareFile("file1", "eve")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	err = u2.ReceiveFile("file2", "alice5", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	_, err9 := u2.LoadFile("file2")

	if err9 != nil {
		t.Error("Failed to load file after share", err9)
		return
	}

	u3, err3 := GetUser("bob", "foobar")
	u3.ReceiveFile("file3", "alice5", m_string)
	if err3 != nil {
		t.Error("Failed to get user", err3)
		return
	}

	u4, err:= InitUser("gg", "gg")

	m4, err24 := u3.ShareFile("file3", "gg")

	if err24 != nil {
		t.Error("Unable to share shared file")
		return
	}

	err25 := u4.ReceiveFile("gg", "bob", m4)

	if err25 != nil {
		t.Error("Unable to receive file twice shared", err25)
		return
	}

	l1, err26 := u4.LoadFile("gg")

	if err26 != nil {
		t.Error("Unable to load file twice shared", err26)
		return
	}

	eq1 := reflect.DeepEqual(l1 , l2)

	if !eq1 {
		t.Error("File shared twice and original file not the same")
		return
	}

	err4 := u.RevokeFile("file1", "bob")

	if err4 != nil {
		t.Error("Failed to revoke file", err4)
		return
	}

	_, err21 := u4.LoadFile("gg")

	if err21 == nil {
		t.Error("Implicitly revoked user able to read file")
		return
	}

	err22 := u4.AppendFile("gg", []byte("gg"))

	if err22 == nil {
		t.Error("Implicitly revoked user able to edit file file")
		return
	}

	_, err5 := u3.LoadFile("file2")
	err10 := u3.AppendFile("File2", []byte("g"))
	u3.ReceiveFile("file3", "alice5", m_string)
	_, err11 := u3.LoadFile("file2")

	if err5 == nil {
		t.Error("Revoked user can still load-file")
		return
	}

	if err10 == nil {
		t.Error("User can append file after revoke")
		return
	}

	if err11 == nil {
		t.Error("User can regain load rights by calling ReceiveFile after revoke")
		return
	}

	_, err6 := u2.LoadFile("file2")

	if err6 != nil {
		t.Error("Unrevoked user can't access file", err6)
		return
	}



	_, err7 := u.LoadFile("file1")

	if err7 != nil {
		t.Error("Owner cannot access file after revoke", err7)
		return
	}

	e2 := u.AppendFile("file1", []byte("noice"))

	if e2 != nil {
		t.Error("Owner could not append after revoke: ", e2)
		return
	}

	e3 := u2.AppendFile("file2", []byte("nooice"))

	if e3 != nil {
		t.Error("Unrevoked the user cannot append file: ", e3)
		return
	}

	b1, e4 := u2.LoadFile("file2")

	if e4 != nil {
		t.Error("Failed to load file after append by unrevoked user :", e4)
		return
	}

	b2, e5 := u.LoadFile("file1")

	if e5 != nil {
		t.Error("Owner unable to load file after unrevoked edit: ", e5)
		return
	}

	eq := reflect.DeepEqual(b1, b2)

	if !eq {
		t.Error("Owner and unrevoked user have different version of file")
		return
	}
}


func testReceiveFile(t *testing.T) {
	//receive a file as the same name as already existing
	u, _ := GetUser("alice", "fubar")
	u2, _ := GetUser("vivi", "yes")

	v := []byte("This is a test")
	v2 := []byte("This is a mess")

	u.StoreFile("file1", v)
	u2.StoreFile("file1", v2)

	magic_string, _ := u.ShareFile("file1", "vivi")
	err := u2.ReceiveFile("file1", "alice", magic_string)

	if err == nil {
		t.Error("Not detecting same name file")
		return
	}
}
