// +build secure

/*
 **********************************
 *
 * Copyright 2017-2018 NXP
 *
 **********************************
 */

package openssl

/*
#cgo LDFLAGS: -lssl -lcrypto
#include <stdio.h>
#include <string.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/ecdsa.h>

typedef unsigned char CK_BYTE;
typedef CK_BYTE * CK_BYTE_PTR;

int C_ECDSA_sign(ENGINE *eng, char *digest, int diglen, CK_BYTE_PTR * sigret, int *siglen, char *key)
{
	EVP_PKEY *privkey;
	EC_KEY *eckey;

	FILE *fp;
	fp = fopen (key, "r");
	privkey = EVP_PKEY_new();
	PEM_read_PrivateKey( fp, &privkey, NULL, NULL);
	fclose(fp);

	ENGINE_set_default(eng, ENGINE_METHOD_ALL);
	OpenSSL_add_all_algorithms();

	eckey = EVP_PKEY_get1_EC_KEY(privkey);

    unsigned char *buffer;
    *siglen = ECDSA_size(eckey);

	*sigret = OPENSSL_malloc(*siglen);
    int rc = ECDSA_sign(0, digest,  diglen,
                       *sigret, siglen, eckey);
	return rc;
}

int C_ECDSA_do_sign(ENGINE *eng, char *digest, char *sigret, char *key)
{
	EVP_PKEY *privkey;
	EC_KEY *eckey;
	ECDSA_SIG *signature = NULL;

	FILE *fp;
	fp = fopen (key, "r");
	privkey = EVP_PKEY_new();
	PEM_read_PrivateKey( fp, &privkey, NULL, NULL);
	fclose(fp);

	ENGINE_set_default(eng, ENGINE_METHOD_ALL);
	OpenSSL_add_all_algorithms();
	//OPENSSL_config(NULL);

	eckey = EVP_PKEY_get1_EC_KEY(privkey);
	signature = ECDSA_do_sign(digest, 20, eckey);

	sigret = BN_bn2hex(signature->r);
	sigret += sprintf(sigret, "%s", BN_bn2hex(signature->s));

	return 0;
}
*/
import "C"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"unsafe"
)

type OpensslPrivateKeyECDSA struct {
	OpensslPrivateKey
	PubKey crypto.PublicKey
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

func ExportECDSAPublicKey(refkey string) (crypto.PublicKey, error) {
	buf, _ := ioutil.ReadFile(refkey)
	block, _ := pem.Decode(buf)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	var asnkey ecPrivateKey
	asn1.Unmarshal(block.Bytes, &asnkey)
	x, y := elliptic.Unmarshal(key.Curve, asnkey.PublicKey.Bytes)

	pub := ecdsa.PublicKey{Curve: key.Curve, X: x, Y: y}

	return &pub, err
}

func (signer *OpensslPrivateKeyECDSA) ECDSA_do_sign(digest []byte) string {
	cdig := C.CString(string(digest))

	var val [128]byte
	sigret := (*C.char)(unsafe.Pointer(&val[0]))

	defer C.free(unsafe.Pointer(sigret))

	C.C_ECDSA_do_sign(signer.Eng, cdig, sigret, C.CString(signer.Key))
	fmt.Println(C.GoString(sigret))
	return C.GoString(sigret)

}

func (signer *OpensslPrivateKeyECDSA) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	var (
		sigret C.CK_BYTE_PTR
		siglen C.int
	)

	dig := string(digest)
	diglen := len(dig)
	var sig []byte
	for {
		C.C_ECDSA_sign(signer.Eng, C.CString(dig), C.int(diglen), &sigret, &siglen, C.CString(signer.Key))
		sig = C.GoBytes(unsafe.Pointer(sigret), C.int(siglen))
		if len(sig) < 71 {
			fmt.Println("ECDSA Sign Failed: sigDERLen=", len(sig), "retry...")
		} else {
			break
		}
	}
	C.free(unsafe.Pointer(sigret))
	return sig, nil
}

func (signer *OpensslPrivateKeyECDSA) Public() crypto.PublicKey {
	return signer.PubKey
}
