package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"

	// optional
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg
	// see someUsefulThings() below
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
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
	Username     []byte
	DSSignKey    []byte
	PKEDecKey    []byte
	File_to_data map[uuid.UUID][][]byte // maps file to file's data
	File_to_user map[uuid.UUID][][]byte //
	Hash         []byte
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
	Share map[uuid.UUID][][]byte
	Key1  []byte
	Key2  []byte
	Key3  []byte
}

type File struct {
	Data [][]byte
	Hash []byte
}

//HMACEval(key1, username (of recipient) || filename)
type Shared struct {
	Uuid    []byte
	Hashkey []byte
	Enckey  []byte
	Sig     []byte
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	b_user := []byte(username)
	b_password := []byte(password)
	key1 := userlib.Argon2Key(b_password, b_user, 16)
	userdata.Username, _ = userlib.HMACEval(key1, b_user)
	key2, _ := userlib.HMACEval(key1, append(b_user, b_password...))
	new_UUID, _ := uuid.FromBytes(key2[:16])
	enckey, deckey, _ := userlib.PKEKeyGen()
	signkey, verkey, _ := userlib.DSKeyGen()
	userlib.KeystoreSet(username, enckey)
	var b_enc []byte
	b_enc, err = json.Marshal(enckey)
	b_enc, err = userlib.HMACEval(b_enc[:16], b_user)
	new_k := string(b_enc)
	userlib.KeystoreSet(new_k, verkey)
	key3 := userlib.Argon2Key(b_password, key2, 16)
	iv1 := userlib.RandomBytes(16)
	userdata.DSSignKey, err = json.Marshal(signkey)
	userdata.PKEDecKey, err = json.Marshal(deckey)
	userdata.DSSignKey = userlib.SymEnc(key3, iv1, userdata.DSSignKey)
	incr_ctr(iv1)
	userdata.PKEDecKey = userlib.SymEnc(key3, iv1, userdata.PKEDecKey)
	userdata.File_to_data = make(map[uuid.UUID][][]byte)
	userdata.File_to_user = make(map[uuid.UUID][][]byte)
	userdata.Share = make(map[uuid.UUID][][]byte)
	userdata.Hash = usr_hash(&userdata, key1)
	//Store the user struct on the datastore after:
	//Encrypting and hashing sign and dec keys
	var data []byte
	data, err = json.Marshal(userdata)
	userlib.DatastoreSet(new_UUID, data)
	userdata.Key1 = key1
	userdata.Key2 = key2
	userdata.Key3 = key3
	return &userdata, nil
}

//From https://www.dotnetperls.com/json-go
// checkout: https://blog.golang.org/why-generics

//increments IV in CTR
//Change to increment by 1
func incr_ctr(b []byte) {
	for i := len(b) - 1; i >= 0; i-- {
		b[i] += 1
		if b[i] != 0 {
			break
		}
	}
}

// hash the user's vital data
func usr_hash(user *User, key []byte) []byte {
	var total []byte
	byte1 := user.DSSignKey
	total = append(total, byte1...)
	byte2 := user.PKEDecKey
	total = append(total, byte2...)
	byte3, _ := json.Marshal(user.File_to_data)
	total = append(total, byte3...)
	byte4, _ := json.Marshal(user.File_to_user)
	total = append(total, byte4...)
	byte5 := user.Username
	total = append(total, byte5...)
	byte6, _ := json.Marshal(user.Share)
	total = append(total, byte6...)
	val, _ := userlib.HMACEval(key, total)
	return val
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	b_password := []byte(password)
	b_user := []byte(username)
	key1 := userlib.Argon2Key(b_password, b_user, 16)
	userdata.Username, err = userlib.HMACEval(key1, b_user)
	key2, _ := userlib.HMACEval(key1, append(b_user, b_password...))
	new_UUID, _ := uuid.FromBytes(key2[:16])
	user_b, ok := userlib.DatastoreGet(new_UUID)
	if !ok {
		return nil, errors.New("Cannot find user")
	}
	err = json.Unmarshal(user_b, &userdata)
	hash := usr_hash(&userdata, key1)
	match := userlib.HMACEqual(hash, userdata.Hash)
	if !match {
		return nil, errors.New("User not matching or corrupted")
	}
	userdataptr = &userdata

	//! PROBLEM IF MULTIPLE GETUSERS CALLS ON SAME USER
	userdata.Key1 = key1
	userdata.Key2 = key2
	userdata.Key3 = userlib.Argon2Key(b_password, key2, 16)
	//go
	return
}

// This stores a file in the datastore.
// The name and length of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	hashkey := userlib.RandomBytes(16)
	enckey := userlib.RandomBytes(16)
	uuid_ := uuid.New()
	var file File
	if len(data) != 0 {
		file.Data = append(file.Data, userlib.SymEnc(enckey, userlib.RandomBytes(16), data))
	}

	file.Hash, _ = userlib.HMACEval(hashkey, flatten2D(file.Data))
	b_file, _ := userlib.HMACEval(userdata.Key1, []byte(filename)) //key to file to data and file to user (same keys)
	e_hash := userlib.SymEnc(userdata.Key3, userlib.RandomBytes(16), hashkey)
	e_key := userlib.SymEnc(userdata.Key3, userlib.RandomBytes(16), enckey)
	var data_ []byte
	data_, _ = json.Marshal(uuid_)
	e_uuid := userlib.SymEnc(userdata.Key3, userlib.RandomBytes(16), data_)
	uuidKey, _ := uuid.FromBytes(b_file[:16])
	userdata.File_to_data[uuidKey] = [][]byte{e_hash, e_key, e_uuid} //overwrites file if two filenames are the same
	userdata.File_to_user[uuidKey] = [][]byte{}
	file_, _ := json.Marshal(file)
	userlib.DatastoreSet(uuid_, file_)
	storeUser(userdata) //update user data structure
	return
}

//Update user structure
func storeUser(user *User) {
	key1 := user.Key1
	key2 := user.Key2
	key3 := user.Key3
	user.Key1 = nil //don't want to send keys to data store
	user.Key2 = nil
	user.Key3 = nil
	user.Hash = usr_hash(user, key1)
	new_UUID, _ := uuid.FromBytes(key2[:16])
	data, _ := json.Marshal(*user)
	userlib.DatastoreSet(new_UUID, data)
	user.Key1 = key1
	user.Key2 = key2
	user.Key3 = key3
}

// Gets file info
func get_file(user *User, filename string) (u uuid.UUID, h []byte, e []byte, f error) {
	id, _ := userlib.HMACEval(user.Key1, []byte(filename))
	uuidKey, _ := uuid.FromBytes(id[:16])
	info, ok := user.File_to_data[uuidKey]
	if ok {
		hashkey := userlib.SymDec(user.Key3, info[0])
		enckey := userlib.SymDec(user.Key3, info[1])
		b_uuid := userlib.SymDec(user.Key3, info[2])
		var uuid uuid.UUID
		_ = json.Unmarshal(b_uuid, &uuid)
		return uuid, hashkey, enckey, nil
	}
	info, ok = user.Share[uuidKey]
	if ok {
		uuid, _ := uuid.FromBytes(userlib.SymDec(user.Key3, info[0])) //16
		var ds userlib.DSVerifyKey
		json.Unmarshal(userlib.SymDec(user.Key3, info[1]), &ds)
		s, ok := userlib.DatastoreGet(uuid)

		if !ok {
			return uuid, nil, nil, errors.New("could find shared struct")
		}

		var share Shared
		json.Unmarshal(s, &share)
		data := flatten2D([][]byte{share.Uuid, share.Hashkey, share.Enckey})
		err := userlib.DSVerify(ds, data, share.Sig)

		if err != nil {
			f = err
			return
		}

		if err == nil {
			var dec userlib.PKEDecKey
			json.Unmarshal(userlib.SymDec(user.Key3, user.PKEDecKey), &dec)
			h, _ = userlib.PKEDec(dec, share.Hashkey)
			e, _ = userlib.PKEDec(dec, share.Enckey)
			u_, _ := userlib.PKEDec(dec, share.Uuid)
			json.Unmarshal(u_, &u)
			f = nil
			return
		}
	}
	f = errors.New("file not found")
	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	uuid, hashkey, enckey, f := get_file(userdata, filename)
	if f != nil {
		return f
	}

	data_, ok := userlib.DatastoreGet(uuid)
	if !ok {
		return errors.New("UUID has changed.")
	}
	iv := userlib.RandomBytes(16)
	var file File
	_ = json.Unmarshal(data_, &file)
	file_hash, _ := userlib.HMACEval(hashkey, flatten2D(file.Data))

	if !userlib.HMACEqual(file_hash, file.Hash) {
		return errors.New("File has been corrupted.")
	}

	file.Data = append(file.Data, userlib.SymEnc(enckey, iv, data))
	file.Hash, _ = userlib.HMACEval(hashkey, flatten2D(file.Data))
	file_, _ := json.Marshal(file)
	userlib.DatastoreSet(uuid, file_)
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	uuid_, hashkey, enckey, f := get_file(userdata, filename)

	if f != nil {
		return nil, f
	}

	data_, ok := userlib.DatastoreGet(uuid_) //encrypted data
	if !ok {
		return nil, errors.New("File does not exist.")
	}
	var file File
	_ = json.Unmarshal(data_, &file)
	hashValue, _ := userlib.HMACEval(hashkey, flatten2D(file.Data))

	if !userlib.HMACEqual(hashValue, file.Hash) {
		return nil, errors.New("File has been corrupted :(")
	}
	//err is nil implicitly
	if len(file.Data) != 0 {
		for _, v := range file.Data {
			data = append(data, userlib.SymDec(enckey, v)...)
		}
		return
	}
	//userlib.DebugMsg("returning file:", string(data))
	return []byte(""), nil

	//Checking corruption before functions
}

//flatten 2D array
func flatten2D(arr [][]byte) []byte {
	var flatArr []byte
	for _, v := range arr {
		flatArr = append(flatArr, v...)
	}
	return flatArr
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
	uuid1, hash, enc, f := get_file(userdata, filename)
	if f != nil {
		return "", f
	}

	_, ok1 := userlib.KeystoreGet(recipient)
	if !ok1 {
		return "", errors.New("recipient not found")
	}
	//storing information about receiver
	id, _ := userlib.HMACEval(userdata.Key1, []byte(filename))
	uuidKey, _ := uuid.FromBytes(id[:16])
	enc_name := userlib.SymEnc(userdata.Key3, userlib.RandomBytes(16), []byte(recipient))
	userdata.File_to_user[uuidKey] = append(userdata.File_to_user[uuidKey], enc_name)
	storeUser(userdata)

	access, _ := userlib.HMACEval(userdata.Key1, append([]byte(filename), []byte(recipient)...))
	access = access[:16]
	enckey, _ := userlib.KeystoreGet(recipient)
	var dskey userlib.DSSignKey
	json.Unmarshal(userlib.SymDec(userdata.Key3, userdata.DSSignKey), &dskey)
	e_access, _ := userlib.PKEEnc(enckey, access)
	ver, err := userlib.DSSign(dskey, e_access)
	if err != nil {
		return "", err
	}
	var share Shared
	share.Enckey, err = userlib.PKEEnc(enckey, enc)
	share.Hashkey, err = userlib.PKEEnc(enckey, hash)
	uuid_, err := json.Marshal(uuid1)
	share.Uuid, err = userlib.PKEEnc(enckey, uuid_)
	share.Sig, err = userlib.DSSign(dskey, flatten2D([][]byte{share.Uuid, share.Hashkey,
		share.Enckey}))
	f_uuid, err := uuid.FromBytes(access)
	b_share, err := json.Marshal(share)
	userlib.DatastoreSet(f_uuid, b_share)
	h_data := [][]byte{e_access, ver}
	t, _ := json.Marshal(h_data)
	magic_string = string(t)
	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	_, _, _, f := get_file(userdata, filename)
	if f == nil {
		return errors.New("file already exists")
	}
	enc, ok := userlib.KeystoreGet(sender)

	if !ok {
		return errors.New("sender not found.")
	}

	b_enc, err := json.Marshal(enc)
	key, err := userlib.HMACEval(b_enc[:16], []byte(sender))

	if err != nil {
		return err
	}

	ds, ok := userlib.KeystoreGet(string(key))

	if !ok {
		return errors.New("user public signature not found")
	}

	b_ds, _ := json.Marshal(ds)
	b_ds = userlib.SymEnc(userdata.Key3, userlib.RandomBytes(16), b_ds)
	byt := []byte(magic_string)
	var info [][]byte
	json.Unmarshal(byt, &info)
	sig := info[1]
	mes := info[0]
	err = userlib.DSVerify(ds, mes, sig)

	if err != nil {
		return errors.New("Error with ds")
	}

	name, _ := userlib.HMACEval(userdata.Key1, []byte(filename))
	// need to enrypt mes with key3.
	var decKey userlib.PKEDecKey
	dec := userlib.SymDec(userdata.Key3, userdata.PKEDecKey)
	err = json.Unmarshal(dec, &decKey)

	if err != nil {
		return errors.New("error with unmarshalling")
	}

	mes, err = userlib.PKEDec(decKey, mes)

	if err != nil {
		return err
	}

	mes = userlib.SymEnc(userdata.Key3, userlib.RandomBytes(16), mes)
	uuidKey, _ := uuid.FromBytes(name[:16])
	userdata.Share[uuidKey] = [][]byte{mes, b_ds}
	return err
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	uuid_, _, _, f := get_file(userdata, filename)
	if f != nil {
		return f
	}


	id, _ := userlib.HMACEval(userdata.Key1, []byte(filename))
	uuidKey, _ := uuid.FromBytes(id[:16])

	//getting file data
	data, err := userdata.LoadFile(filename)
	if err != nil {
		return err
	}

	userlib.DatastoreDelete(uuid_)
	temp := userdata.File_to_user[uuidKey]
	userdata.StoreFile(filename, data)
	userdata.File_to_user[uuidKey] = [][]byte{}

	for _, val := range temp {
		dec := userlib.SymDec(userdata.Key3, val)
		if string(dec) != target_username {
			_, err = userdata.ShareFile(filename, string(dec))

			if err != nil {
				return err
			}
		}

	}
	return
}
