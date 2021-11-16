package main

/*
#cgo CFLAGS: -I . -I ./asn1c
#include <stdio.h>
#include <Rectangle.h>

static void decode(char* buffer, int length) {
    Rectangle_t *pdu = 0;                      // Type to encode
    asn_dec_rval_t rval;                       // Decoder return value
    pdu = calloc(1, sizeof(Rectangle_t));      // not malloc!
	rval = aper_decode_complete(0, &asn_DEF_Rectangle, (void **)&pdu, buffer, length);
	xer_fprint(stdout, &asn_DEF_Rectangle, pdu);
}
*/
import "C"

func main() {

	//encode

	//decode
}
