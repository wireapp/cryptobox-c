package main


// #cgo CFLAGS: -I/usr/include -I../src
// #cgo LDFLAGS: -L../target/release  -L/usr/lib/x86_64-linux-gnu  -lcryptoboxdb
// #include <cbox.h>
// #include <stdlib.h>
// #include <stdint.h>
// #include <string.h>
// #include <memory.h>
import "C"

import (
	"os"
	"fmt"
	"unsafe"
	"github.com/pborman/uuid"
)
// char* charAlloc(int n) {char str[n]; return str;}
// CBox* cboxalloc() { CBox * alice_box = NULL; return alice_box; }
// CBoxSession* cboxSessionalloc() { CBoxSession * session = NULL; return session; }
// CBoxVec* cboxVecAlloc() { CBoxVec * cipher = NULL; return cipher; }
func main() {

	aliceuuId:=GetUUID()
	aliceId := C.CString(aliceuuId)
	bobuuId:=GetUUID()
	bobId := C.CString(bobuuId)
	dburl := C.CString("postgresql://han@localhost:26257/cbox")

	//alice_box := C.cboxalloc()
	var alice_box *C.CBox
	var bob_box *C.CBox
	var dbconn1 *C.Armconn
	var dbconn2 *C.Armconn
	var pool *C.ConnPool
	//bob_box := C.cboxalloc()
	fmt.Println("db starting...")

	if rc := C.cbox_db_conn_pool(dburl,15,&pool); rc!=C.CBOX_SUCCESS{
		panic(fmt.Sprintf("cbox_db_conn_pool failed...CboxResult is: %d",rc))
	}
	fmt.Println("DB pool build finished ...")

	if rc := C.cbox_db_conn(pool, &dbconn1); rc!=C.CBOX_SUCCESS{
		panic(fmt.Sprintf("cbox_db_conn failed...CboxResult is: %d",rc))
	}
	fmt.Println("get conn1 from db pool  finished ...")

	if rc := C.cbox_db_conn(pool, &dbconn2); rc!=C.CBOX_SUCCESS{
		panic(fmt.Sprintf("cbox_db_conn failed...CboxResult is: %d",rc))
	}
	fmt.Println("get conn2 from db pool  finished ...")


	fmt.Println("db ok...uuid is :",bobuuId)
	C.cbox_db_open(aliceId, dbconn1, &alice_box)
	C.cbox_db_open(bobId, dbconn2, &bob_box)

	test_basic(alice_box, bob_box)
	// Cleanup
	C.cbox_close(alice_box)
	C.cbox_close(bob_box)
	C.cbox_conn_pool_close(pool)
	C.cbox_conn_close(dbconn1)
	C.cbox_conn_close(dbconn2)
	fmt.Println("Every thing are being released  successfully  ")
}



// path test
//func main() {
//	if exist, err := PathExists("cbox_test_aliceXXXXXX"); !exist || err != nil {
//		os.MkdirAll("cbox_test_aliceXXXXXX", 0755)
//		os.MkdirAll("cbox_test_bobXXXXXX", 0755)
//	}
//
//	alicedir := C.CString("cbox_test_aliceXXXXXX")
//	bobdir := C.CString("cbox_test_bobXXXXXX")
//	//alice_box := C.cboxalloc()
//	var alice_box *C.CBox
//	var bob_box *C.CBox
//	//bob_box := C.cboxalloc()
//	C.cbox_file_open(alicedir, &alice_box)
//	C.cbox_file_open(bobdir, &bob_box)
//
//	test_basic(alice_box, bob_box)
//	// Cleanup
//	C.cbox_close(alice_box)
//	C.cbox_close(bob_box)
//}
func test_basic(alice_box *C.struct_CBox ,bob_box *C.struct_CBox ){

	fmt.Println("basic test starting...")
	// Bob prekey
	var bob_prekey *C.CBoxVec
	//bob_prekey:=C.cboxVecAlloc()
	//rc = cbox_new_prekey(bob_box, 1, &bob_prekey);
	if rc := C.cbox_new_prekey(bob_box, 1, &bob_prekey); rc!=C.CBOX_SUCCESS{
		panic(fmt.Sprintf("cbox_new_prekey failed...CboxResult is: %d",rc))
	}


	// Alice
	//CBoxSession * alice = NULL;
	var alice *C.CBoxSession
	//alice:=C.cboxSessionalloc()
	//rc = cbox_session_init_from_prekey(alice_box, "alice", cbox_vec_data(bob_prekey), cbox_vec_len(bob_prekey), &alice);
	//assert(rc == CBOX_SUCCESS);
	if rc := C.cbox_session_init_from_prekey(alice_box, C.CString("alice"), C.cbox_vec_data(bob_prekey), C.cbox_vec_len(bob_prekey), &alice); rc!=C.CBOX_SUCCESS{
		panic("cbox_session_init_from_prekey failed...")
	}

	if rc := C.cbox_session_save(alice_box, alice); rc!=C.CBOX_SUCCESS{
		panic("cbox_session_save failed...")
	}
	//char const * hello_bob = "Hello Bob!";
	//CBoxVec * cipher = NULL;
	//rc = cbox_encrypt(alice, hello_bob, sizeof(hello_bob), &cipher);
	//assert(rc == CBOX_SUCCESS);
	hello_bob0 := C.CString("Hello Bob!")
	hello_bob :=(*C.uchar)(unsafe.Pointer(hello_bob0))
	//s:=(C.ulong)(unsafe.Sizeof(*hello_bob))
	hello_bob_len := C.strlen(hello_bob0)
	fmt.Println("hello_bob size is: ",hello_bob_len)
	//cipher:=C.cboxVecAlloc()
	var cipher *C.CBoxVec
	if rc := C.cbox_encrypt(alice, hello_bob, hello_bob_len, &cipher); rc!=C.CBOX_SUCCESS{
		panic("cbox_encrypt failed...")
	}

	cipher0:=(*C.char)(unsafe.Pointer(C.cbox_vec_data(cipher)))

	if assert(C.strncmp(hello_bob0, cipher0, hello_bob_len) != 0){
		panic("cbox_encrypt failed2...")
	}
	// Bob
	//CBoxSession * bob = NULL;
	//CBoxVec * plain = NULL;
	//rc = cbox_session_init_from_message(bob_box, "bob", cbox_vec_data(cipher), cbox_vec_len(cipher), &bob, &plain);
	//assert(rc == CBOX_SUCCESS);
	//bob:=C.cboxSessionalloc()
	//plain:=C.cboxVecAlloc()
	var bob *C.CBoxSession
	var plain *C.CBoxVec
	if rc := C.cbox_session_init_from_message(bob_box, C.CString("bob"), C.cbox_vec_data(cipher), C.cbox_vec_len(cipher), &bob, &plain); rc!=C.CBOX_SUCCESS{
		panic("cbox_session_init_from_message failed...")
	}
	if rc := C.cbox_session_save(bob_box, bob); rc!=C.CBOX_SUCCESS{
		panic("bob cbox_session_save failed...")
	}
	plain0:=(*C.char)(unsafe.Pointer(C.cbox_vec_data(plain)))
	//var plain1 *[10]C.char
	//plain1 :=C.charAlloc(C.int(hello_bob_len)) 生存期问题不能用
	s:=make([]byte, hello_bob_len)
	plain1:=C.CString(string(s))
	//C.memset(unsafe.Pointer(plain1),0,hello_bob_len);
	C.memcpy(unsafe.Pointer(plain1),unsafe.Pointer(plain0),hello_bob_len)
	if assert(C.strncmp(hello_bob0, plain1, hello_bob_len) == 0){
			panic("cbox_decrypt failed...")
		}
	fmt.Println("hello_bob0 is: ", C.GoString(hello_bob0))
	fmt.Println("plain is: ", C.GoString(plain1))

	// Load the sessions again
	C.cbox_session_close(alice)
	C.cbox_session_close(bob)
	rc := C.cbox_session_load(alice_box, C.CString("alice"), &alice)
	if assert(rc == C.CBOX_SUCCESS){
		panic("alice cbox_session_load failed...")
	}
	rc = C.cbox_session_load(bob_box, C.CString("bob"), &bob)
	if assert(rc == C.CBOX_SUCCESS){
		panic("bob cbox_session_load failed...")
	}

	// unknown session
	//unknown:=C.cboxSessionalloc()
	var unknown *C.CBoxSession
	rc = C.cbox_session_load(alice_box, C.CString("unknown"), &unknown)
	if assert(rc == C.CBOX_SESSION_NOT_FOUND){
		panic("unknown cbox_session_load failed...")
	}

	// Cleanup
	C.cbox_vec_free(cipher)
	C.cbox_vec_free(plain)
	C.cbox_vec_free(bob_prekey)

	C.cbox_session_close(alice)
	C.cbox_session_close(bob)


}

func assert (a bool) bool {

	return !a
}

func GetUUID() string {
	return uuid.New()
	//return strings.Join(strings.Split(uuid.New(), "-"), "")
}


func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}