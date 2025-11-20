package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	"strconv"
)

// Encrypt the given message with a key derived from the given key by the given purpose.
func encrypt(msg []byte, key []byte, purpose string) (encrypted_msg []byte, err error) {
	derived_key, err := userlib.HashKDF(key, []byte(purpose))
	if err != nil {
		return nil, err
	}
	derived_key = derived_key[:16]
	iv := userlib.RandomBytes(16)
	encrypted_msg = userlib.SymEnc(derived_key, iv, msg)
	return encrypted_msg, nil
}

// Decrypt the given message with a key derived from the given key by the given purpose.
func decrypt(encrypted_msg []byte, key []byte, purpose string) (msg []byte, err error) {
	derived_key, err := userlib.HashKDF(key, []byte(purpose))
	if err != nil {
		return nil, err
	}
	derived_key = derived_key[:16]
	if len(encrypted_msg) < 16 {
		return nil, fmt.Errorf("the ciphertext length %d is smaller than AES-CTR blocksize, purpose: %s", len(encrypted_msg), purpose)
	}
	msg = userlib.SymDec(derived_key, encrypted_msg)
	return msg, nil
}

// Store the message into the datastore at the given UUID with an added HMAC for integrity
func hmac_store(msg_uuid uuid.UUID, msg []byte, key []byte, purpose string) error {
	// we add "hmac:" so the same purpose can be used for encrypting and HMACing
	derived_key, err := userlib.HashKDF(key, []byte("hmac:"+purpose))
	if err != nil {
		return err
	}
	derived_key = derived_key[:16]

	hmac, err := userlib.HMACEval(derived_key, msg)
	if err != nil {
		return err
	}

	if len(hmac) != 64 {
		return fmt.Errorf("oops hmac has length %d", len(hmac))
	}

	hmac_msg := make([]byte, 64+len(msg))
	copy(hmac_msg, hmac)
	copy(hmac_msg[64:], msg)

	userlib.DatastoreSet(msg_uuid, hmac_msg)
	return nil
}

// Load the message from the datastore at the given UUID, checking the HMAC from auth_store for integrity
func hmac_load(msg_uuid uuid.UUID, key []byte, purpose string) (msg []byte, err error) {
	derived_key, err := userlib.HashKDF(key, []byte("hmac:"+purpose))
	if err != nil {
		return nil, err
	}
	derived_key = derived_key[:16]

	hmac_msg, ok := userlib.DatastoreGet(msg_uuid)
	if !ok {
		return nil, errors.New("there is nothing to hmac_load at that uuid")
	}

	if len(hmac_msg) < 64 {
		return nil, errors.New("there is no HMAC tag on this message")
	}
	hmac := hmac_msg[:64]
	msg = make([]byte, len(hmac_msg)-64)
	copy(msg, hmac_msg[64:]) // want to make sure we're returning a clean slice for sanity purposes

	hmac2, err := userlib.HMACEval(derived_key, msg)
	if err != nil {
		return nil, err
	}
	equal := userlib.HMACEqual(hmac, hmac2)
	if !equal {
		return nil, errors.New("the HMAC on this message is invalid or the provided key is wrong")
	}
	return msg, nil
}

// Store the message into the datastore at the given UUID with an added digital signature for integrity
// The tag is hashed, then stored and signed along with the message for additional integrity
func ds_store(msg_uuid uuid.UUID, msg []byte, key userlib.DSSignKey, tag []byte) error {
	tag_hash := userlib.Hash(tag)[:16]
	tagged_msg := make([]byte, 16+len(msg))
	copy(tagged_msg, tag_hash)
	copy(tagged_msg[16:], msg)

	sig, err := userlib.DSSign(key, tagged_msg)
	if err != nil {
		return err
	}

	if len(sig) != 256 {
		return fmt.Errorf("oops signature has length %d", len(sig))
	}

	signed_msg := make([]byte, 256+len(tagged_msg))
	copy(signed_msg, sig)
	copy(signed_msg[256:], tagged_msg)

	userlib.DatastoreSet(msg_uuid, signed_msg)
	return nil
}

// Load the message from the datastore at the given UUID, checking the digital signature from ds_store for integrity
// The tag is also checked for integrity
func ds_load(msg_uuid uuid.UUID, key userlib.DSVerifyKey, tag []byte) (msg []byte, err error) {
	tag_hash := userlib.Hash(tag)[:16]
	signed_msg, ok := userlib.DatastoreGet(msg_uuid)
	if !ok {
		return nil, errors.New("there is nothing to ds_load at that uuid")
	}

	if len(signed_msg) < 256+16 {
		return nil, errors.New("there is no signature+tag on this message")
	}
	sig := signed_msg[:256]
	tagged_msg := signed_msg[256:]

	err = userlib.DSVerify(key, tagged_msg, sig)
	if err != nil {
		return nil, err
	}

	tag_hash2 := tagged_msg[:16]
	msg = make([]byte, len(tagged_msg)-16)
	copy(msg, tagged_msg[16:]) // want to make sure we're returning a clean slice for sanity purposes
	equal := userlib.HMACEqual(tag_hash, tag_hash2)
	if !equal {
		return nil, errors.New("this message has an invalid tag")
	}

	return msg, nil
}

type User struct {
	PasswordHash []byte // The hash of the user’s root key to check for logins.
	PrivateKey   []byte // The user’s private key, marshaled then encrypted by the user’s root key.
	SignKey      []byte // The user's signing key, marshaled then encrypted by the user's root key.

	username string // the user's username
	rootkey  []byte // the 16-byte PBKDF of the user’s password with their username as salt, used to derive all other keys
}

type File struct {
	Sharer     string    //  the sharer of the file if it is shared, otherwise empty string.
	Location   uuid.UUID // a pointer to the file header.
	SharedWith uuid.UUID // a pointer to a list of all users the file was shared with.
}

type Share struct {
	FileAccessPtr     uuid.UUID // a pointer to a digitally signed access point provided by the file owner pointing to the file header.
	ContentRootKey    []byte    // the RSA-encrypted symmetric key that derives keys to decrypt the file contents.
	OriginalRecipient string    // the user that the file owner originally shared it with.
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	// Check if the username is empty
	if username == "" {
		return nil, errors.New("the username cannot be 0 characters")
	}

	// Generate the user's corresponding UUID
	useruuid, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, err
	}
	// Check if a user already exists at that UUID
	_, exists := userlib.DatastoreGet(useruuid)
	if exists {
		return nil, errors.New("a user with that username already exists")
	}

	// If not, create the user struct
	var userdata User
	userdata.username = username

	// Generate the user's root key, and save its hash
	userdata.rootkey = userlib.Argon2Key([]byte(password), []byte(username), 16)
	userdata.PasswordHash = userlib.Hash(userdata.rootkey)

	// Generate and store the RSA keys
	pub, priv, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	userlib.KeystoreSet("public:"+username, pub)
	priv_bytes, err := json.Marshal(priv)
	if err != nil {
		return nil, err
	}
	userdata.PrivateKey, err = encrypt(priv_bytes, userdata.rootkey, "ENK key")
	if err != nil {
		return nil, err
	}

	// Generate and store the DS keys
	sign, verify, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	userlib.KeystoreSet("verify:"+username, verify)
	sign_bytes, err := json.Marshal(sign)
	if err != nil {
		return nil, err
	}
	userdata.SignKey, err = encrypt(sign_bytes, userdata.rootkey, "DS key")
	if err != nil {
		return nil, err
	}

	// Marshal and store the user struct
	userbytes, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}
	hmac_store(useruuid, userbytes, userdata.rootkey, "User")

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	// Generate the user's corresponding UUID
	useruuid, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, err
	}
	// Generate the user's corresponding root key
	rootkey := userlib.Argon2Key([]byte(password), []byte(username), 16)

	// Check if a user exists at that UUID, and fetch it if so
	userbytes, err := hmac_load(useruuid, rootkey, "User")
	if err != nil {
		return nil, err
	}

	// Get the user struct
	var userdata User
	err = json.Unmarshal(userbytes, &userdata)
	if err != nil {
		return nil, err
	}

	// Check if the password (ie. root key) is correct
	pwhash := userlib.Hash(rootkey)
	correct := userlib.HMACEqual(userdata.PasswordHash, pwhash)
	if !correct {
		return nil, errors.New("the password is incorrect")
	}

	// Finish initializing the user struct
	userdata.username = username
	userdata.rootkey = rootkey

	return &userdata, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// Generate the UUID for the file: apply PBKDF to the filename with the username as salt.
	fileuuid, err := uuid.FromBytes(userlib.Argon2Key([]byte(filename), []byte(userdata.username), 16))
	if err != nil {
		return err
	}

	// Check if the file exists
	_, exists := userlib.DatastoreGet(fileuuid)

	// If necessary, create the File struct, then JSON marshal it and store it at the file’s UUID.
	var filedata File
	if exists {
		// Fetch the file struct
		filebytes, err := hmac_load(fileuuid, userdata.rootkey, "File"+filename)
		if err != nil {
			return err
		}
		err = json.Unmarshal(filebytes, &filedata)
		if err != nil {
			return err
		}
	} else {
		// Create the File struct
		filedata = File{Sharer: "", Location: uuid.New(), SharedWith: uuid.New()}

		// Store the File struct
		filebytes, err := json.Marshal(filedata)
		if err != nil {
			return err
		}
		err = hmac_store(fileuuid, filebytes, userdata.rootkey, "File"+filename)
		if err != nil {
			return err
		}

		// At the SharedWith UUID, store an empty list (json marshaled)
		sharedwith, err := json.Marshal(make([]string, 0))
		if err != nil {
			return err
		}
		err = hmac_store(filedata.SharedWith, sharedwith, userdata.rootkey, "shared"+filename)
		if err != nil {
			return err
		}
	}

	// Retrieve a pointer to the file header and the content root key
	var headeruuid uuid.UUID
	var content_rootkey []byte
	if filedata.Sharer != "" {
		// Fetch the invite
		verifykey, ok := userlib.KeystoreGet("verify:" + filedata.Sharer)
		if !ok {
			return errors.New("could not find the sharer's verify key")
		}
		invite_bytes, err := ds_load(filedata.Location, verifykey, []byte(userdata.username))
		if err != nil {
			return err
		}
		var invite Share
		err = json.Unmarshal(invite_bytes, &invite)
		if err != nil {
			return err
		}

		// Decrypt the content root key
		privkey_bytes, err := decrypt(userdata.PrivateKey, userdata.rootkey, "ENK key")
		if err != nil {
			return err
		}
		var privkey userlib.PKEDecKey
		err = json.Unmarshal(privkey_bytes, &privkey)
		if err != nil {
			return err
		}
		content_rootkey, err = userlib.PKEDec(privkey, invite.ContentRootKey)
		if err != nil {
			return err
		}

		// Collect the header pointer from the file access point
		headeruuid_bytes, err := hmac_load(invite.FileAccessPtr, content_rootkey, "access"+invite.OriginalRecipient)
		if err != nil {
			return err
		}
		headeruuid, err = uuid.FromBytes(headeruuid_bytes)
		if err != nil {
			return err
		}
	} else {
		headeruuid = filedata.Location

		// Generate the file's content root key for the file encryption
		content_rootkey, err = userlib.HashKDF(userdata.rootkey, []byte("content:"+filename))
		if err != nil {
			return err
		}
		content_rootkey = content_rootkey[:16]
	}

	// At the UUID where the file will be stored, store the marshaled integer 1 (# of file pieces)
	header, err := json.Marshal(int(1))
	if err != nil {
		return err
	}
	err = hmac_store(headeruuid, header, content_rootkey, "header")
	if err != nil {
		return err
	}

	// Pass this UUID into HashKDF with purpose "0" and slice to get a new UUID for the first piece of the file
	content0_loc, err := userlib.HashKDF(headeruuid[:], []byte("0"))
	if err != nil {
		return err
	}
	content0_uuid, err := uuid.FromBytes(content0_loc[:16])
	if err != nil {
		return err
	}

	// At this UUID store the encrypted file contents.
	content_enc, err := encrypt(content, content_rootkey, "0")
	if err != nil {
		return err
	}
	err = hmac_store(content0_uuid, content_enc, content_rootkey, "0")
	if err != nil {
		return err
	}

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// Generate the UUID for the file
	fileuuid, err := uuid.FromBytes(userlib.Argon2Key([]byte(filename), []byte(userdata.username), 16))
	if err != nil {
		return nil, err
	}

	// Fetch the File struct (or error if it doesn't exist)
	filebytes, err := hmac_load(fileuuid, userdata.rootkey, "File"+filename)
	if err != nil {
		return nil, err
	}
	var filedata File
	err = json.Unmarshal(filebytes, &filedata)
	if err != nil {
		return nil, err
	}

	// Retrieve a pointer to the file header and the content root key
	var headeruuid uuid.UUID
	var content_rootkey []byte
	if filedata.Sharer != "" {
		// Fetch the invite
		verifykey, ok := userlib.KeystoreGet("verify:" + filedata.Sharer)
		if !ok {
			return nil, errors.New("could not find the sharer's verify key")
		}
		invite_bytes, err := ds_load(filedata.Location, verifykey, []byte(userdata.username))
		if err != nil {
			return nil, err
		}
		var invite Share
		err = json.Unmarshal(invite_bytes, &invite)
		if err != nil {
			return nil, err
		}

		// Decrypt the content root key
		privkey_bytes, err := decrypt(userdata.PrivateKey, userdata.rootkey, "ENK key")
		if err != nil {
			return nil, err
		}
		var privkey userlib.PKEDecKey
		err = json.Unmarshal(privkey_bytes, &privkey)
		if err != nil {
			return nil, err
		}
		content_rootkey, err = userlib.PKEDec(privkey, invite.ContentRootKey)
		if err != nil {
			return nil, err
		}

		// Collect the header pointer from the file access point
		headeruuid_bytes, err := hmac_load(invite.FileAccessPtr, content_rootkey, "access"+invite.OriginalRecipient)
		if err != nil {
			return nil, err
		}
		headeruuid, err = uuid.FromBytes(headeruuid_bytes)
		if err != nil {
			return nil, err
		}
	} else {
		headeruuid = filedata.Location

		// Generate the file's content root key for the file encryption
		content_rootkey, err = userlib.HashKDF(userdata.rootkey, []byte("content:"+filename))
		if err != nil {
			return nil, err
		}
		content_rootkey = content_rootkey[:16]
	}

	// Get the number of pieces from the file header
	header, err := hmac_load(headeruuid, content_rootkey, "header")
	if err != nil {
		return nil, err
	}
	var filelen int
	err = json.Unmarshal(header, &filelen)
	if err != nil {
		return nil, err
	}

	// for each piece we derive the UUID for that index, decrypt, and concatenate together the pieces to recover the original file
	content = make([]byte, 0)
	for i := 0; i < filelen; i++ {
		// Derive the uuid for this piece
		contenti_loc, err := userlib.HashKDF(headeruuid[:], []byte(strconv.Itoa(i)))
		if err != nil {
			return nil, err
		}
		contenti_uuid, err := uuid.FromBytes(contenti_loc[:16])
		if err != nil {
			return nil, err
		}

		// Decrypt this piece
		contenti_enc, err := hmac_load(contenti_uuid, content_rootkey, strconv.Itoa(i))
		if err != nil {
			return nil, err
		}
		contenti, err := decrypt(contenti_enc, content_rootkey, strconv.Itoa(i))
		if err != nil {
			return nil, err
		}

		// Concatenate
		content = append(content, contenti...)
	}

	return content, nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// Follow the same protocol as LoadFile to reach the files header UUID (including handling shared files).

	// Generate the UUID for the file, and check if it exists.
	fileuuid, err := uuid.FromBytes(userlib.Argon2Key([]byte(filename), []byte(userdata.username), 16))
	if err != nil {
		return err
	}
	filebytes, err := hmac_load(fileuuid, userdata.rootkey, "File"+filename)
	if err != nil {
		return err
	}

	// Get the File struct
	var filedata File
	err = json.Unmarshal(filebytes, &filedata)
	if err != nil {
		return err
	}

	// Retrieve a pointer to the file header and the content root key
	var headeruuid uuid.UUID
	var content_rootkey []byte
	if filedata.Sharer != "" {
		// Fetch the invite
		verifykey, ok := userlib.KeystoreGet("verify:" + filedata.Sharer)
		if !ok {
			return errors.New("could not find the sharer's verify key")
		}
		invite_bytes, err := ds_load(filedata.Location, verifykey, []byte(userdata.username))
		if err != nil {
			return err
		}
		var invite Share
		err = json.Unmarshal(invite_bytes, &invite)
		if err != nil {
			return err
		}

		// Decrypt the content root key
		privkey_bytes, err := decrypt(userdata.PrivateKey, userdata.rootkey, "ENK key")
		if err != nil {
			return err
		}
		var privkey userlib.PKEDecKey
		err = json.Unmarshal(privkey_bytes, &privkey)
		if err != nil {
			return err
		}
		content_rootkey, err = userlib.PKEDec(privkey, invite.ContentRootKey)
		if err != nil {
			return err
		}

		// Collect the header pointer from the file access point
		headeruuid_bytes, err := hmac_load(invite.FileAccessPtr, content_rootkey, "access"+invite.OriginalRecipient)
		if err != nil {
			return err
		}
		headeruuid, err = uuid.FromBytes(headeruuid_bytes)
		if err != nil {
			return err
		}
	} else {
		headeruuid = filedata.Location

		// Generate the file's content root key for the file encryption
		content_rootkey, err = userlib.HashKDF(userdata.rootkey, []byte("content:"+filename))
		if err != nil {
			return err
		}
		content_rootkey = content_rootkey[:16]
	}

	// Get the number of pieces from the file header
	header, err := hmac_load(headeruuid, content_rootkey, "header")
	if err != nil {
		return err
	}
	var filelen int
	err = json.Unmarshal(header, &filelen)
	if err != nil {
		return err
	}

	// Increment the number of pieces by one and store it again.
	header, err = json.Marshal(int(filelen + 1))
	if err != nil {
		return err
	}
	err = hmac_store(headeruuid, header, content_rootkey, "header")
	if err != nil {
		return err
	}

	// Derive the appropriate UUID of the file at this index
	next_loc, err := userlib.HashKDF(headeruuid[:], []byte(strconv.Itoa(filelen)))
	if err != nil {
		return err
	}
	next_uuid, err := uuid.FromBytes(next_loc[:16])
	if err != nil {
		return err
	}

	// Store the encrypted appended portion of the file
	content_enc, err := encrypt(content, content_rootkey, strconv.Itoa(filelen))
	if err != nil {
		return err
	}
	err = hmac_store(next_uuid, content_enc, content_rootkey, strconv.Itoa(filelen))
	if err != nil {
		return err
	}

	return nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	// Generate the UUID for the file
	fileuuid, err := uuid.FromBytes(userlib.Argon2Key([]byte(filename), []byte(userdata.username), 16))
	if err != nil {
		return uuid.Nil, err
	}

	// Fetch the File struct (or error if it doesn't exist)
	filebytes, err := hmac_load(fileuuid, userdata.rootkey, "File"+filename)
	if err != nil {
		return uuid.Nil, err
	}
	var filedata File
	err = json.Unmarshal(filebytes, &filedata)
	if err != nil {
		return uuid.Nil, err
	}

	// Decrypt the signing key
	signkey_bytes, err := decrypt(userdata.SignKey, userdata.rootkey, "DS key")
	if err != nil {
		return uuid.Nil, err
	}
	var signkey userlib.DSSignKey
	err = json.Unmarshal(signkey_bytes, &signkey)
	if err != nil {
		return uuid.Nil, err
	}

	var fileaccessptr uuid.UUID
	var content_rootkey []byte
	var originalrecipient string
	// If the file is itself shared, the struct’s Location points to an invitation, which we fetch and collect the values we need.
	if filedata.Sharer != "" {
		// Fetch the invitation for this file.
		sharer_verifykey, ok := userlib.KeystoreGet("verify:" + filedata.Sharer)
		if !ok {
			return uuid.Nil, errors.New("could not find the sharer's verify key")
		}
		oldinvite_bytes, err := ds_load(filedata.Location, sharer_verifykey, []byte(userdata.username))
		if err != nil {
			return uuid.Nil, err
		}
		var oldinvite Share
		err = json.Unmarshal(oldinvite_bytes, &oldinvite)
		if err != nil {
			return uuid.Nil, err
		}

		// Collect the file access ptr and the content root key
		fileaccessptr = oldinvite.FileAccessPtr
		privkey_bytes, err := decrypt(userdata.PrivateKey, userdata.rootkey, "ENK key")
		if err != nil {
			return uuid.Nil, err
		}
		var privkey userlib.PKEDecKey
		err = json.Unmarshal(privkey_bytes, &privkey)
		if err != nil {
			return uuid.Nil, err
		}
		content_rootkey, err = userlib.PKEDec(privkey, oldinvite.ContentRootKey)
		if err != nil {
			return uuid.Nil, err
		}

		// Collect the original recipient
		originalrecipient = oldinvite.OriginalRecipient

	} else { // If the file is not shared, create the access point.
		// Hash together the file struct UUID with the recipient’s username to get the access point UUID.
		accessbytes, err := userlib.HashKDF(fileuuid[:], []byte(recipientUsername))
		if err != nil {
			return uuid.Nil, err
		}
		fileaccessptr, err = uuid.FromBytes(accessbytes[:16])
		if err != nil {
			return uuid.Nil, err
		}

		// Generate the content file's content root key
		content_rootkey, err = userlib.HashKDF(userdata.rootkey, []byte("content:"+filename))
		if err != nil {
			return uuid.Nil, err
		}
		content_rootkey = content_rootkey[:16]

		// Store an HMACed pointer to the file header at this access point.
		hmac_store(fileaccessptr, filedata.Location[:], content_rootkey, "access"+recipientUsername)

		// Set the original recipient of the file to the current recipient
		originalrecipient = recipientUsername

		// Update the file's SharedWith list with the new recipient
		sharedwith_bytes, err := hmac_load(filedata.SharedWith, userdata.rootkey, "shared"+filename)
		if err != nil {
			return uuid.Nil, err
		}
		var sharedwith []string
		err = json.Unmarshal(sharedwith_bytes, &sharedwith)
		if err != nil {
			return uuid.Nil, err
		}
		sharedwith = append(sharedwith, recipientUsername)
		sharedwith_bytes, err = json.Marshal(sharedwith)
		if err != nil {
			return uuid.Nil, err
		}
		err = hmac_store(filedata.SharedWith, sharedwith_bytes, userdata.rootkey, "shared"+filename)
		if err != nil {
			return uuid.Nil, err
		}
	}

	// Create and fill the Share struct
	recipient_publickey, ok := userlib.KeystoreGet("public:" + recipientUsername)
	if !ok {
		return uuid.Nil, errors.New("couldn't find the recipient user's public key")
	}
	content_rootkey_enc, err := userlib.PKEEnc(recipient_publickey, content_rootkey)
	if err != nil {
		return uuid.Nil, err
	}
	invitation := Share{FileAccessPtr: fileaccessptr, ContentRootKey: content_rootkey_enc, OriginalRecipient: originalrecipient}

	// Generate a random UUID at which we store the Share struct
	inviteuuid := uuid.New()
	invitation_bytes, err := json.Marshal(invitation)
	if err != nil {
		return uuid.Nil, err
	}
	err = ds_store(inviteuuid, invitation_bytes, signkey, []byte(recipientUsername))
	if err != nil {
		return uuid.Nil, err
	}

	return inviteuuid, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// Check that the invitation did come from senderUsername
	verify, ok := userlib.KeystoreGet("verify:" + senderUsername)
	if !ok {
		return errors.New("the sender of the invitation does not exist")
	}
	invite_bytes, err := ds_load(invitationPtr, verify, []byte(userdata.username))
	if err != nil {
		return err
	}

	// Fetch the access pointer from the invite struct and check if the access was revoked
	var invite Share
	err = json.Unmarshal(invite_bytes, &invite)
	if err != nil {
		return err
	}
	_, ok = userlib.DatastoreGet(invite.FileAccessPtr)
	if !ok {
		return errors.New("cannot accept a revoked invitation")
	}

	// Generate the UUID for the file: apply PBKDF to the filename with the username as salt.
	fileuuid, err := uuid.FromBytes(userlib.Argon2Key([]byte(filename), []byte(userdata.username), 16))
	if err != nil {
		return err
	}

	// Check if the file exists
	_, exists := userlib.DatastoreGet(fileuuid)
	if exists {
		return errors.New("shared file name already exists in this namespace")
	}

	// Create the File struct with Sharer set to the sender and location pointing to the invitation.
	filedata := File{Sharer: senderUsername, Location: invitationPtr, SharedWith: uuid.Nil}

	// Store the File struct
	filebytes, err := json.Marshal(filedata)
	if err != nil {
		return err
	}
	err = hmac_store(fileuuid, filebytes, userdata.rootkey, "File"+filename)
	if err != nil {
		return err
	}

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// Generate the UUID for the file
	fileuuid, err := uuid.FromBytes(userlib.Argon2Key([]byte(filename), []byte(userdata.username), 16))
	if err != nil {
		return err
	}

	// Fetch the File struct (or error if it doesn't exist)
	filebytes, err := hmac_load(fileuuid, userdata.rootkey, "File"+filename)
	if err != nil {
		return err
	}
	var filedata File
	err = json.Unmarshal(filebytes, &filedata)
	if err != nil {
		return err
	}

	// Fetch the SharedWith list
	sharedwith_bytes, err := hmac_load(filedata.SharedWith, userdata.rootkey, "shared"+filename)
	if err != nil {
		return err
	}
	var sharedwith []string
	err = json.Unmarshal(sharedwith_bytes, &sharedwith)
	if err != nil {
		return err
	}

	// Check if the revoked user is a recipient
	revoked_index := -1
	for i, user := range sharedwith {
		if user == recipientUsername {
			revoked_index = i
			break
		}
	}
	if revoked_index == -1 {
		return errors.New("the revoked user must be a file recipient")
	}

	// Remove the revoked user from the shared list
	new_sharedwith := make([]string, 0)
	new_sharedwith = append(new_sharedwith, sharedwith[:revoked_index]...)
	new_sharedwith = append(new_sharedwith, sharedwith[revoked_index+1:]...)
	new_sharedwith_bytes, err := json.Marshal(new_sharedwith)
	if err != nil {
		return err
	}

	// Save the updated SharedWith list
	err = hmac_store(filedata.SharedWith, new_sharedwith_bytes, userdata.rootkey, "shared"+filename)
	if err != nil {
		return err
	}

	// Download the file contents
	filecontents, err := userdata.LoadFile(filename)
	if err != nil {
		return err
	}

	// Update the file's Location to a new random UUID
	new_uuid := uuid.New()
	filedata.Location = new_uuid
	filebytes, err = json.Marshal(filedata)
	if err != nil {
		return err
	}
	err = hmac_store(fileuuid, filebytes, userdata.rootkey, "File"+filename)
	if err != nil {
		return err
	}

	// Store the file contents at this new location
	err = userdata.StoreFile(filename, filecontents)
	if err != nil {
		return err
	}

	// Generate the file's content root key
	content_rootkey, err := userlib.HashKDF(userdata.rootkey, []byte("content:"+filename))
	if err != nil {
		return err
	}
	content_rootkey = content_rootkey[:16]

	// Delete the revoked user's access point
	accessuuid_bytes, err := userlib.HashKDF(fileuuid[:], []byte(recipientUsername))
	if err != nil {
		return err
	}
	accessuuid, err := uuid.FromBytes(accessuuid_bytes[:16])
	if err != nil {
		return err
	}
	userlib.DatastoreDelete(accessuuid)

	// Update the access points for the remaining users
	for _, user := range new_sharedwith {
		// Generate the user's access point uuid
		accessuuid_bytes, err := userlib.HashKDF(fileuuid[:], []byte(user))
		if err != nil {
			return err
		}
		accessuuid, err := uuid.FromBytes(accessuuid_bytes[:16])
		if err != nil {
			return err
		}

		// Update the access point with the new file location
		err = hmac_store(accessuuid, new_uuid[:], content_rootkey, "access"+user)
		if err != nil {
			return err
		}
	}

	return nil
}
