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

typedef unsigned char CK_BYTE;
typedef CK_BYTE * CK_BYTE_PTR;

int C_ExportRSAPublicKey(ENGINE *eng, CK_BYTE_PTR *n, CK_BYTE_PTR *e, char *key) {
	EVP_PKEY *privkey;
	RSA *rsakey;

	FILE *fp;
	fp = fopen (key, "r");
	privkey = EVP_PKEY_new();
	PEM_read_PrivateKey(fp, &privkey, NULL, NULL);
	fclose(fp);

	ENGINE_set_default(eng, ENGINE_METHOD_ALL);

	rsakey = EVP_PKEY_get1_RSA(privkey);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	*e = BN_bn2dec(rsakey->e);
	*n = BN_bn2hex(rsakey->n);
#else
    const BIGNUM *bn_n, *bn_e;
	RSA_get0_key(rsakey, &bn_n, &bn_e, NULL);
	*e = BN_bn2dec(bn_e);
	*n = BN_bn2hex(bn_n);
#endif
	return 0;
}

int C_RSA_sign(ENGINE *eng, char *digest, int diglen, CK_BYTE_PTR * sigret, int *siglen, char *key)
{
	EVP_PKEY *privkey;
	RSA *rsakey;

	FILE *fp;
	fp = fopen (key, "r");
	privkey = EVP_PKEY_new();
	PEM_read_PrivateKey(fp, &privkey, NULL, NULL);
	fclose(fp);

	ENGINE_set_default(eng, ENGINE_METHOD_ALL);
	rsakey = EVP_PKEY_get1_RSA(privkey);

	*sigret = malloc(256);
	int rc = RSA_sign(NID_sha256, digest, diglen, *sigret, siglen, rsakey);
	return rc;
}
*/
import "C"

import (
	"crypto"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"strconv"
	"unsafe"
)

type OpensslPrivateKeyRSA struct {
	OpensslPrivateKey
	PubKey crypto.PublicKey
}

func ExportRSAPublicKey(eng *C.ENGINE, key string) (crypto.PublicKey, error) {
	var (
		n C.CK_BYTE_PTR
		e C.CK_BYTE_PTR
	)
	var modulus = new(big.Int)
	C.C_ExportRSAPublicKey(eng, &n, &e, C.CString(key))
	h, _ := hex.DecodeString(C.GoString((*C.char)(unsafe.Pointer(n))))
	modulus.SetBytes(h)
	E, _ := strconv.Atoi(C.GoString((*C.char)(unsafe.Pointer(e))))

	pub := rsa.PublicKey{N: modulus, E: E}
	if pub.E < 2 {
		return nil, errors.New("crypto11/rsa: malformed RSA key")
	}
	C.free(unsafe.Pointer(n))

	return &pub, nil
}

func (signer *OpensslPrivateKeyRSA) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	var (
		sigret C.CK_BYTE_PTR
		siglen C.int
	)

	dig := string(digest)
	diglen := len(dig)
	rc := C.C_RSA_sign(signer.Eng, C.CString(dig), C.int(diglen), &sigret, &siglen, C.CString(signer.Key))
	if rc != 1 {
		return nil, errors.New("sobj sign failed")
	}
	sig := C.GoBytes(unsafe.Pointer(sigret), C.int(siglen))
	C.free(unsafe.Pointer(sigret))
	return sig, nil
}

func (signer *OpensslPrivateKeyRSA) Public() crypto.PublicKey {
	return signer.PubKey
}

func ParseSobjPrivateKey(block []byte) (int, error) {
	type pkcs1AdditionalRSAPrime struct {
		Prime *big.Int
		Exp   *big.Int
		Coeff *big.Int
	}

	type pkcs1PrivateKey struct {
		Version int
		N       *big.Int
		E       int
		D       *big.Int
		P       *big.Int
		Q       *big.Int
		Dp      *big.Int `asn1:"optional"`
		Dq      *big.Int `asn1:"optional"`
		Qinv    *big.Int `asn1:"optional"`

		AdditionalPrimes []pkcs1AdditionalRSAPrime `asn1:"optional,omitempty"`
	}

	var priv pkcs1PrivateKey
	_, err := asn1.Unmarshal(block, &priv)
	D := hex.EncodeToString(priv.D.Bytes())
	index := len(D)
	key_id := D[index-24 : index-8]
	if key_id == "e1e2e3e4e1e2e3e4" {
		id, err := strconv.Atoi(D[index-2:])
		return id, err
	}
	return -1, err
}
