package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/google/uuid"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Error and Functionality Tests", func() {

		Describe("User Tests", func() {

			Describe("InitUser", func() {
				// Error if a user with the same username exists.
				Specify("InitUser: Error if an user with the same username exists.", func() {
					userlib.DebugMsg("Initializing user Alice.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Initializing another user with the same name.")
					_, err = client.InitUser("alice", defaultPassword)
					Expect(err).ToNot(BeNil())
				})

				// Error if an empty username is provided.
				Specify("InitUser: Error if an empty username is provided.", func() {
					userlib.DebugMsg("Initializing user with empty name.")
					_, err = client.InitUser("", defaultPassword)
					Expect(err).ToNot(BeNil())
				})
			})

			Describe("GetUser", func() {
				// Error if the user does not exist.
				Specify("GetUser: Error if the user does not exist.", func() {
					userlib.DebugMsg("Initializing user Bob.")
					bob, err = client.InitUser("bob", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Getting a user that doesn't exist.")
					_, err = client.GetUser("alice", defaultPassword)
					Expect(err).ToNot(BeNil())
				})

				// Error if the password is incorrect.
				Specify("GetUser: Error if the password is incorrect.", func() {
					userlib.DebugMsg("Initializing user Alice.")
					alice, err = client.InitUser("alice", "cat")
					Expect(err).To(BeNil())

					userlib.DebugMsg("Getting user Alice with the wrong password.")
					_, err = client.GetUser("alice", "dog")
					Expect(err).ToNot(BeNil())
				})
			})

			// Other User tests

			// Usernames are case-sensitive.
			Specify("Users: Usernames are case-sensitive.", func() {
				userlib.DebugMsg("Initializing user alice.")
				alice, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Initializing user Alice.")
				_, err = client.InitUser("Alice", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Attempting to get user ALICE.")
				_, err = client.GetUser("ALICE", defaultPassword)
				Expect(err).ToNot(BeNil())
			})

			// Passwords are any string of 0 or more characters.
			Specify("Users: Passwords may have 0 characters.", func() {
				userlib.DebugMsg("Initializing user Alice.")
				alice, err = client.InitUser("alice", "")
				Expect(err).To(BeNil())

				userlib.DebugMsg("Getting user Alice.")
				alice, err = client.GetUser("alice", "")
				Expect(err).To(BeNil())

				userlib.DebugMsg("Getting user Alice with nonempty password.")
				alice, err = client.InitUser("alice", " ")
				Expect(err).ToNot(BeNil())
			})
		})

		Describe("File Operations Tests", func() {

			BeforeEach(func() {
				userlib.DebugMsg("Initializing user Alice.")
				alice, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())
			})

			Describe("StoreFile", func() {
				// Stores a new file if the filename doesn’t exist in the namespace.
				Specify("StoreFile: Stores a new file if the filename doesn't exist in the namespace.", func() {
					userlib.DebugMsg("User %s storing file %s with content %s.", "Alice", aliceFile, contentOne)
					err = alice.StoreFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Loading alice's file.")
					data, err := alice.LoadFile(aliceFile)
					Expect(err).To(BeNil())
					Expect(data).To(Equal([]byte(contentOne)))
				})

				// Overwrites the existing file if the filename exists in the namespace.
				Specify("StoreFile: Overwrites the existing file if the filename exists in the namespace.", func() {
					userlib.DebugMsg("User %s storing file %s with content %s.", "Alice", aliceFile, contentOne)
					err = alice.StoreFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Overwriting alice's file.")
					err = alice.StoreFile(aliceFile, []byte(contentTwo))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Loading alice's file.")
					data, err := alice.LoadFile(aliceFile)
					Expect(err).To(BeNil())
					Expect(data).To(Equal([]byte(contentTwo)))
				})

				// Filenames are any string of 0 or more characters.
				Specify("StoreFile: Filenames may be empty.", func() {
					userlib.DebugMsg("Alice is storing a file with an empty name.")
					err = alice.StoreFile("", []byte(contentOne))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Alice is loading her file with empty name.")
					data, err := alice.LoadFile("")
					Expect(err).To(BeNil())
					Expect(data).To(Equal([]byte(contentOne)))
				})
			})

			Describe("LoadFile", func() {
				// Error if filename doesn’t exist in namespace.
				Specify("LoadFile: Error if filename doesn't exist in namespace.", func() {
					userlib.DebugMsg("User %s storing file %s with content %s.", "alice", aliceFile, contentOne)
					err = alice.StoreFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Alice is attempting to load a file that doesn't exist.")
					_, err = alice.LoadFile("not alice's file")
					Expect(err).ToNot(BeNil())
				})
			})

			Describe("AppendToFile", func() {
				// Error if filename doesn’t exist in namespace.
				Specify("AppendToFile: Error if filename doesn't exist in namespace.", func() {
					userlib.DebugMsg("User %s storing file %s with content %s.", "alice", aliceFile, contentOne)
					err = alice.StoreFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Alice is attempting to append to a file that doesn't exist.")
					err = alice.AppendToFile("not alice's file", []byte(contentOne))
					Expect(err).ToNot(BeNil())
				})

				// Bandwidth: The total amount of data uploaded with DatastoreGet,
				// 	and downloaded with DatastoreSet, must be a constant. Bandwidth
				//	can only scale with the size of the data being appended.
				//	Compute, time, space, etc. does not matter for efficiency,
				//	only bandwidth.
				Specify("AppendToFile: The total bandwidth of AppendToFile must be constant.", func() {
					// TODO: This is a subtle thing to check.

				})

			})

			// Other File tests
			// Namespace: Different users could use the same filename, but they could refer to different files.
			//		Test for loading and appending
			Specify("File Operations: Different users could use the same filename, but they could refer to different files.", func() {
				userlib.DebugMsg("Initializing user Bob.")
				bob, err = client.InitUser("bob", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Making alice's cat file.")
				err = alice.StoreFile("cat", []byte(contentOne))
				Expect(err).To(BeNil())

				userlib.DebugMsg("Making bob's cat file.")
				err = bob.StoreFile("cat", []byte(contentTwo))
				Expect(err).To(BeNil())

				userlib.DebugMsg("Check that Alice's file is unmodified.")
				data, err := alice.LoadFile("cat")
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentOne)))

				userlib.DebugMsg("Append to Alice's file.")
				err = alice.AppendToFile("cat", []byte(contentThree))
				Expect(err).To(BeNil())

				userlib.DebugMsg("Check that Bob's file is unmodified.")
				data, err = bob.LoadFile("cat")
				Expect(err).To(BeNil())
				Expect(data).To(Equal([]byte(contentTwo)))
			})
		})

		Describe("Sharing and Revoking Tests", func() {

			BeforeEach(func() {
				userlib.DebugMsg("Initializing user Alice.")
				alice, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Initializing user Bob.")
				bob, err = client.InitUser("bob", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Initializing user Charlie.")
				charles, err = client.InitUser("charles", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Initializing user Doris.")
				doris, err = client.InitUser("doris", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("User %s storing file %s with content %s.", "alice", aliceFile, contentOne)
				err = alice.StoreFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())
			})

			Describe("CreateInvitation", func() {
				// Error if filename doesn’t exist in namespace.
				Specify("CreateInvitation: Error if filename doesn't exist in namespace.", func() {
					userlib.DebugMsg("Attempting to share a file that doesn't exist.")
					_, err := alice.CreateInvitation("Not alice's file", "bob")
					Expect(err).ToNot(BeNil())
				})

				// Error if recipient user doesn’t exist.
				Specify("CreateInvitation: Error if recipient user doesn't exist.", func() {
					userlib.DebugMsg("Attempting to share a file that doesn't exist.")
					_, err := alice.CreateInvitation(aliceFile, "nonexistant user")
					Expect(err).ToNot(BeNil())
				})
			})

			Describe("AcceptInvitation", func() {
				// The recipient can choose their own filename (possibly different) for the shared file in their own namespace.
				Specify("AcceptInvitation: The recipient can choose their own filename.", func() {
					userlib.DebugMsg("Alice shares the file with Bob.")
					invite1, err := alice.CreateInvitation(aliceFile, "bob")
					Expect(err).To(BeNil())

					userlib.DebugMsg("Alice shares the file with Charlie.")
					invite2, err := alice.CreateInvitation(aliceFile, "charles")
					Expect(err).To(BeNil())

					userlib.DebugMsg("Bob accepts the invite with a new name.")
					err = bob.AcceptInvitation("alice", invite1, bobFile)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Charlie accepts the invite with the same name.")
					err = charles.AcceptInvitation("alice", invite2, aliceFile)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Charlie shares the file with Doris")
					invite3, err := charles.CreateInvitation(aliceFile, "doris")
					Expect(err).To(BeNil())

					userlib.DebugMsg("Doris accepts the invite with the same name.")
					err = doris.AcceptInvitation("charles", invite3, aliceFile)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Check that Alice can still access the file.")
					data, err := alice.LoadFile(aliceFile)
					Expect(err).To(BeNil())
					Expect(data).To(Equal([]byte(contentOne)))

					userlib.DebugMsg("Make a new file for bob called " + aliceFile + ".")
					err = bob.StoreFile(aliceFile, []byte(contentTwo))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Check that Bob can access Alice's file.")
					data, err = bob.LoadFile(bobFile)
					Expect(err).To(BeNil())
					Expect(data).To(Equal([]byte(contentOne)))

					userlib.DebugMsg("Check that Charlie can access Alice's file.")
					data, err = charles.LoadFile(aliceFile)
					Expect(err).To(BeNil())
					Expect(data).To(Equal([]byte(contentOne)))

					userlib.DebugMsg("Check that Doris can access Alice's file.")
					data, err = doris.LoadFile(aliceFile)
					Expect(err).To(BeNil())
					Expect(data).To(Equal([]byte(contentOne)))
				})

				// Error if the sender of the invitation is wrong.
				Specify("AcceptInvitation: Error if the sender of the invitation doesn't exist.", func() {
					userlib.DebugMsg("Sharing the file with Bob.")
					invite, err := alice.CreateInvitation(aliceFile, "bob")
					Expect(err).To(BeNil())

					userlib.DebugMsg("Accepting the invite with the wrong name.")
					err = bob.AcceptInvitation("nonexistant user", invite, bobFile)
					Expect(err).ToNot(BeNil())
				})

				// Error if the chosen filename already exists.
				Specify("AcceptInvitation: Error if the chosen filename already exists.", func() {
					userlib.DebugMsg("Sharing the file with Bob.")
					invite, err := alice.CreateInvitation(aliceFile, "bob")
					Expect(err).To(BeNil())

					userlib.DebugMsg("User %s storing file %s with content %s.", "bob", bobFile, contentTwo)
					err = bob.StoreFile(bobFile, []byte(contentTwo))
					Expect(err).To(BeNil())

					userlib.DebugMsg("Bob accepts the invite with an already existing filename.")
					err = bob.AcceptInvitation("alice", invite, bobFile)
					Expect(err).ToNot(BeNil())
				})

				// Error if the invitation UUID cannot be processed.
				Specify("AcceptInvitation: Error if the invitation UUID cannot be processed.", func() {
					userlib.DebugMsg("Bob attempts to accept an invite with a nil UUID.")
					err = bob.AcceptInvitation("alice", uuid.Nil, bobFile)
					Expect(err).ToNot(BeNil())

					userlib.DebugMsg("Bob attempts to accept an invite with a random UUID.")
					err = bob.AcceptInvitation("alice", uuid.New(), bobFile)
					Expect(err).ToNot(BeNil())
				})

				// Error if the invitation UUID is invalidated from a revoke.
				Specify("AcceptInvitation: Error if the invitation UUID is invalidated from a revoke.", func() {
					userlib.DebugMsg("Sharing the file with Bob.")
					invite, err := alice.CreateInvitation(aliceFile, "bob")
					Expect(err).To(BeNil())

					userlib.DebugMsg("Revoking access from Bob.")
					err = alice.RevokeAccess(aliceFile, "bob")
					Expect(err).To(BeNil())

					userlib.DebugMsg("Bob attempts to accept the revoked invitation.")
					err = bob.AcceptInvitation("alice", invite, bobFile)
					Expect(err).ToNot(BeNil())
				})

			})

			Describe("RevokeAccess", func() {
				// Revoked users should get an error when trying to access the file (e.g. load, store, etc.).
				Specify("RevokeAccess: Revoked users should get an error when trying to access the file.", func() {
					userlib.DebugMsg("Alice shares her file with Bob.")
					invite, err := alice.CreateInvitation(aliceFile, "bob")
					Expect(err).To(BeNil())

					userlib.DebugMsg("Bob accepts her invitation.")
					err = bob.AcceptInvitation("alice", invite, bobFile)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Alice revokes access from Bob.")
					err = alice.RevokeAccess(aliceFile, "bob")
					Expect(err).To(BeNil())

					userlib.DebugMsg("Bob should no longer be able to load the file.")
					_, err = bob.LoadFile(bobFile)
					Expect(err).ToNot(BeNil())

					userlib.DebugMsg("Bob should no longer be able to store to the file.")
					err = bob.StoreFile(bobFile, []byte(contentTwo))
					Expect(err).ToNot(BeNil())

					userlib.DebugMsg("Bob should no longer be able to append to the file.")
					err = bob.AppendToFile(bobFile, []byte(contentTwo))
					Expect(err).ToNot(BeNil())
				})

				// Non-revoked users should be able to continue accessing the file without needing to re-accept any invitations.
				Specify("RevokeAccess: Non-revoked users should be able to continue accessing the file.", func() {

				})

				// Secondary recipients should also have their access revoked.
				Specify("RevokeAccess: Secondary recipients should also have their access revoked.", func() {
					userlib.DebugMsg("Alice shares her file with Bob.")
					invite, err := alice.CreateInvitation(aliceFile, "bob")
					Expect(err).To(BeNil())

					userlib.DebugMsg("Bob accepts her invitation.")
					err = bob.AcceptInvitation("alice", invite, bobFile)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Bob shares the file with Charlie.")
					invite, err = bob.CreateInvitation(bobFile, "charles")
					Expect(err).To(BeNil())

					userlib.DebugMsg("Charlie accepts his invitation.")
					err = charles.AcceptInvitation("bob", invite, charlesFile)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Charlie accesses the file.")
					_, err = charles.LoadFile(charlesFile)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Alice revokes access from Bob.")
					err = alice.RevokeAccess(aliceFile, "bob")
					Expect(err).To(BeNil())

					userlib.DebugMsg("Charlie should no longer be able to load the file.")
					_, err = charles.LoadFile(charlesFile)
					Expect(err).ToNot(BeNil())

					userlib.DebugMsg("Charlie should no longer be able to store to the file.")
					err = charles.StoreFile(charlesFile, []byte(contentTwo))
					Expect(err).ToNot(BeNil())

					userlib.DebugMsg("Charlie should no longer be able to append to the file.")
					err = charles.AppendToFile(charlesFile, []byte(contentTwo))
					Expect(err).ToNot(BeNil())
				})

				// Error if filename doesn’t exist, or target user doesn’t have access.

			})

			//		General:
			//			The owner, and anybody who has accepted an invitation, should be able to access the file
			//				(load, store, append, create invitations).
			Specify("Sharing and Revoking: The owner, and anybody who has accepted an invitation, should be able to access the file", func() {
				userlib.DebugMsg("Alice shares the file with Bob.")
				invite1, err := alice.CreateInvitation(aliceFile, "bob")
				Expect(err).To(BeNil())

				userlib.DebugMsg("Alice shares the file with Charlie.")
				invite2, err := alice.CreateInvitation(aliceFile, "charles")
				Expect(err).To(BeNil())

				userlib.DebugMsg("Bob accepts the invite.")
				err = bob.AcceptInvitation("alice", invite1, bobFile)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Charlie accepts the invite.")
				err = charles.AcceptInvitation("alice", invite2, charlesFile)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Charlie shares the file with Doris")
				invite3, err := charles.CreateInvitation(charlesFile, "doris")
				Expect(err).To(BeNil())

				userlib.DebugMsg("Doris accepts the invite.")
				err = doris.AcceptInvitation("charles", invite3, dorisFile)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Bob loads the file.")
				content, err := bob.LoadFile(bobFile)
				Expect(err).To(BeNil())
				Expect(content).To(Equal([]byte(contentOne)))

				userlib.DebugMsg("Bob updates the file.")
				err = bob.StoreFile(bobFile, []byte(contentTwo))
				Expect(err).To(BeNil())

				userlib.DebugMsg("Bob appends to the file.")
				err = bob.AppendToFile(bobFile, []byte(contentThree))
				Expect(err).To(BeNil())

				userlib.DebugMsg("Doris loads the file.")
				content, err = doris.LoadFile(dorisFile)
				Expect(err).To(BeNil())
				Expect(content).To(Equal([]byte(contentTwo + contentThree)))

				userlib.DebugMsg("Doris updates the file.")
				err = doris.StoreFile(dorisFile, []byte(contentOne))
				Expect(err).To(BeNil())

				userlib.DebugMsg("Doris appends to the file.")
				err = doris.AppendToFile(dorisFile, []byte(contentTwo))
				Expect(err).To(BeNil())
			})
		})

		//	Concurrency Tests
		//		Any more complex issues here that don't fit easily into above?
		//		eg. multiple devices, need to test with all different functions
		//
		//		Users must be able to create multiple User instances on different devices.
		//		All changes to files made from one device must be reflected on all other devices immediately.
		//
		//

		//	Datastore Attacker Tests
		Describe("Datastore Adversary Tests", func() {

			Describe("Integrity Tests", func() {
				// Helper function that deletes all entries in the datastore.
				delete_datastore := func() {
					userlib.DebugMsg("Deleting the contents of datastore.")
					datastore := userlib.DatastoreGetMap()
					for k := range datastore {
						delete(datastore, k)
					}
				}

				// Helper function that replaces all datastore entries with garbage.
				trash_datastore := func() {
					userlib.DebugMsg("Overwriting the contents of datastore.")
					datastore := userlib.DatastoreGetMap()
					for k := range datastore {
						datastore[k] = []byte("garbage")
					}
				}

				// Helper function that replaces all datastore entries with the entry added by the given malicious operation
				hack_datastore := func(operation func() error) {
					userlib.DebugMsg("Hacking the contents of datastore")
					datastore := userlib.DatastoreGetMap()

					// copy the current state of datastore
					pre_datastore := make(map[userlib.UUID][]byte)
					for k, v := range datastore {
						pre_datastore[k] = v
					}

					err = operation()
					Expect(err).To(BeNil())

					// find the uuid of the newly added entry (there may be several such uuids when storing a file)
					var new_uuid userlib.UUID
					for uuid := range datastore {
						if _, ok := pre_datastore[uuid]; !ok {
							new_uuid = uuid
							break
						}
					}

					// Overwrite datastore with copies of this new properly serialized entry
					userlib.DebugMsg("Overwriting the contents of datastore.")
					for k := range datastore {
						datastore[k] = datastore[new_uuid]
					}
				}

				BeforeEach(func() {
					userlib.DebugMsg("Initializing user Alice.")
					alice, err = client.InitUser("alice", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("User %s storing file %s with content %s.", "alice", aliceFile, contentOne)
					err = alice.StoreFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())
				})

				// Error if the User struct was deleted
				Specify("Datastore-GetUser: Error if he User struct was deleted.", func() {
					delete_datastore()

					userlib.DebugMsg("Attempting to login Alice.")
					_, err := client.GetUser("alice", defaultPassword)
					Expect(err).ToNot(BeNil())
				})

				// Error if the User struct cannot be obtained due to malicious action.
				Specify("Datastore-GetUser: Error if he User struct cannot be obtained due to malicious action.", func() {
					trash_datastore()

					userlib.DebugMsg("Attempting to login Alice.")
					_, err := client.GetUser("alice", defaultPassword)
					Expect(err).ToNot(BeNil())
				})

				// Error if the integrity of the user struct has been compromised.
				Specify("Datastore-GetUser: Error if the integrity of the user struct has been compromised.", func() {
					malicious_user := func() error {
						_, err = client.InitUser("min", "somi")
						return err
					}

					userlib.DebugMsg("Replacing datastore with a malicious user.")
					hack_datastore(malicious_user)

					userlib.DebugMsg("Attempting to login Alice.")
					_, err := client.GetUser("alice", defaultPassword)
					Expect(err).ToNot(BeNil())
				})

				// Error if the file was deleted.
				Specify("Datastore-LoadFile: Error if the file was deleted.", func() {
					delete_datastore()

					userlib.DebugMsg("Attempting to access Alice's file.")
					_, err := alice.LoadFile(aliceFile)
					Expect(err).ToNot(BeNil())
				})

				// Error if the file can't be loaded due to malicious action.
				Specify("Datastore-LoadFile: Check for corruption when loading a file.", func() {
					trash_datastore()

					userlib.DebugMsg("Attempting to access Alice's file.")
					_, err := alice.LoadFile(aliceFile)
					Expect(err).ToNot(BeNil())
				})

				// Error if the integrity of the file being loaded has been compromised.
				Specify("Datastore-LoadFile: Check for integrity when loading a file.", func() {
					malicious_store := func() error {
						return alice.StoreFile("SHELLCODE", []byte(contentTwo))
					}

					userlib.DebugMsg("Replacing datastore with a malicious file.")
					hack_datastore(malicious_store)

					userlib.DebugMsg("Attempting to access Alice's file.")
					_, err := alice.LoadFile(aliceFile)
					Expect(err).ToNot(BeNil())
				})

				// Error if the file can't be appended to because it was deleted.
				Specify("Datastore-AppendToFile: Check for corruption when appending to a file.", func() {
					delete_datastore()

					userlib.DebugMsg("Attempting to append to Alice's file.")
					err := alice.AppendToFile(aliceFile, []byte(contentTwo))
					Expect(err).ToNot(BeNil())
				})

				// Error if the file can't be appended due to malicious action.
				Specify("Datastore-AppendToFile: Check for corruption when appending to a file.", func() {
					trash_datastore()

					userlib.DebugMsg("Attempting to append to Alice's file.")
					err := alice.AppendToFile(aliceFile, []byte(contentTwo))
					Expect(err).ToNot(BeNil())
				})

				// Error if the integrity of the file being appended has been compromised.
				Specify("Datastore-AppendToFile: Check for integrity when appending to a file.", func() {
					malicious_store := func() error {
						return alice.StoreFile("SHELLCODE", []byte(contentTwo))
					}

					userlib.DebugMsg("Replacing datastore with a malicious file.")
					hack_datastore(malicious_store)

					userlib.DebugMsg("Attempting to append to Alice's file.")
					err := alice.AppendToFile(aliceFile, []byte(contentTwo))
					Expect(err).ToNot(BeNil())
				})

				// AcceptInvitation:

				Specify("Datastore-AcceptInvitation: Error if invitation was deleted.", func() {
					userlib.DebugMsg("Initializing user Bob.")
					bob, err = client.InitUser("bob", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Creating an invitation for Bob.")
					invite, err := alice.CreateInvitation(aliceFile, "bob")
					Expect(err).To(BeNil())

					delete_datastore()

					userlib.DebugMsg("Attempting to accept deleted invitation.")
					err = bob.AcceptInvitation("alice", invite, bobFile)
					Expect(err).ToNot(BeNil())
				})

				// 		Error if the invitation is corrupted (modified) in the datastore
				Specify("Datastore-AcceptInvitation: Check for corruption when accepting an invitation.", func() {
					userlib.DebugMsg("Initializing user Bob.")
					bob, err = client.InitUser("bob", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Creating an invitation for Bob.")
					invite, err := alice.CreateInvitation(aliceFile, "bob")
					Expect(err).To(BeNil())

					trash_datastore()

					userlib.DebugMsg("Attempting to accept trashed invitation.")
					err = bob.AcceptInvitation("alice", invite, bobFile)
					Expect(err).ToNot(BeNil())
				})

				Specify("Datastore-AcceptInvitation: Check for integrity when accepting an invitation.", func() {
					userlib.DebugMsg("Initializing user Bob.")
					bob, err = client.InitUser("bob", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Creating an invitation for Bob.")
					invite, err := alice.CreateInvitation(aliceFile, "bob")
					Expect(err).To(BeNil())

					userlib.DebugMsg("Initializing user Charlie.")
					charles, err = client.InitUser("charles", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Initializing user Doris.")
					doris, err = client.InitUser("doris", defaultPassword)
					Expect(err).To(BeNil())

					userlib.DebugMsg("Charlie creates a file.")
					err = charles.StoreFile(charlesFile, []byte(contentTwo))
					Expect(err).To(BeNil())

					malicious_invite := func() error {
						_, err = charles.CreateInvitation(charlesFile, "doris")
						return err
					}

					userlib.DebugMsg("Replacing datastore with a malicious invite.")
					hack_datastore(malicious_invite)

					userlib.DebugMsg("Attempting to accept modified invitation.")
					err = bob.AcceptInvitation("alice", invite, bobFile)
					Expect(err).ToNot(BeNil())
				})
			})
		})

		//	Revoked User Attacker Tests
		// 		Revoked users should be unable to regain access, even if they maliciously use Datastore.
		//		Not sure how to test this
		//
		//	(Can we test for confidentiality?)
	})

	//////////////// DEFAULT TESTS ////////////////

	Describe("Default Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})
})
