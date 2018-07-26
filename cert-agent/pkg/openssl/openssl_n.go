// +build !secure

/*
 **********************************
 *
 * Copyright 2018 NXP
 *
 **********************************
 */

package openssl

/*
#include<stdio.h>

typedef char ENGINE;
ENGINE *C_Sobj_Engine_Init() {
		ENGINE *eng=NULL;
		return eng;
}
*/
import "C"

import (
	"crypto"
)

// Not implemented. Reserved for future use.
func Sobj_Init() *C.ENGINE {
	eng := C.C_Sobj_Engine_Init()
	return eng
}

// Not implemented. Reserved for future use.
func (eng *C.ENGINE) Sobj_KeyGen(key string, id int) crypto.PrivateKey {
	return nil
}

// Not implemented. Reserved for future use.
func (eng *C.ENGINE) Sobj_Loadkey(key string) (crypto.PrivateKey, error) {
	return nil, nil
}

// Not implemented. Reserved for future use.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	return nil, nil
}

// Not implemented. Reserved for future use.
func ParseSobjPrivateKey(block []byte) (int, error) {
	return 0, nil
}
