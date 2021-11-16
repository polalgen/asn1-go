package main

/*
#cgo CFLAGS: -I. -I./asn1c
#cgo LDFLAGS: -L. -ls1ap

#include <S1AP-PDU.h>

void decode(void* buffer, int length) {
    S1AP_PDU_t *pdu = 0;                       // Type to decode
	pdu = calloc(1, sizeof(S1AP_PDU_t));	   // allocate struct for decode
    asn_dec_rval_t rval;                       // Decoder return value
	rval = aper_decode_complete(0, &asn_DEF_S1AP_PDU, (void **)&pdu, buffer, length);
	xer_fprint(stdout, &asn_DEF_S1AP_PDU, pdu);
}
*/
import "C"
import (
	"fmt"
	"io/ioutil"
	"os"
	"unsafe"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Print("Usage: decode [filename]\n")
		os.Exit(0)
	}
	filename := os.Args[1]
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("File read error:", err)
	}
	// call decode
	C.decode(unsafe.Pointer(&content[0]), C.int(len(content)))
}
