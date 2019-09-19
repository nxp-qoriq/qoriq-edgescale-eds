// +build secure se

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
#include <openssl/ssl.h>
#include <openssl/engine.h>

ENGINE *C_Sobj_Engine_Init(char* path) {
	ENGINE * eng;
	const char *engine_id = "dynamic";

	ENGINE_load_builtin_engines();
	eng = ENGINE_by_id(engine_id);
	if (!eng) {
		printf("ENGINE_by_id failed\n");
	}
	ENGINE_ctrl_cmd_string(eng, "SO_PATH", path, 0);
	ENGINE_ctrl_cmd_string(eng, "LOAD", NULL, 0);
	return eng;
}

*/
import "C"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"unsafe"
)

var EnginePath = ""

type OpensslPrivateKey struct {
	Key string
	Eng *C.ENGINE
}
type ENGINE *C.ENGINE

func Sobj_Init() *C.ENGINE {
	cPath := C.CString(EnginePath)
	defer C.free(unsafe.Pointer(cPath))
	eng := C.C_Sobj_Engine_Init(cPath)
	return eng
}

func (eng *C.ENGINE) Sobj_Loadkey(key string) (crypto.PrivateKey, error) {
	pub, err := ExportRSAPublicKey(eng, key)
	priv := &OpensslPrivateKeyRSA{OpensslPrivateKey{key, eng}, pub}
	return priv, err
}

func (eng *C.ENGINE) Sobj_LoadECkey(key string) (crypto.PrivateKey, error) {
	pub, err := ExportECDSAPublicKey(key)
	priv := &OpensslPrivateKeyECDSA{OpensslPrivateKey{key, eng}, pub}
	return priv, err
}

func (eng *C.ENGINE) Sobj_KeyGen(key string, id int) crypto.PrivateKey {
	cmd := fmt.Sprintf("sobj_app  -L -l %s | grep handle |awk '{print $4}' | xargs -i sobj_app -R -h {}", key)
	exec.Command("bash", "-c", cmd).Run()

	cmd = fmt.Sprintf("sobj_app -G -m rsa-pair -s 2048 -l %s -i %d -w %s", key, id, key)
	exec.Command("bash", "-c", cmd).Run()
	priv, _ := eng.Sobj_Loadkey(key)
	return priv
}

func X509KeyPair(certPEMBlock, keyPEMBlock []byte, keyfile string) (tls.Certificate, error) {
	fail := func(err error) (tls.Certificate, error) { return tls.Certificate{}, err }

	var cert tls.Certificate
	var skippedBlockTypes []string
	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		} else {
			skippedBlockTypes = append(skippedBlockTypes, certDERBlock.Type)
		}
	}

	if len(cert.Certificate) == 0 {
		if len(skippedBlockTypes) == 0 {
			return fail(errors.New("crypto/tls: failed to find any PEM data in certificate input"))
		} else if len(skippedBlockTypes) == 1 && strings.HasSuffix(skippedBlockTypes[0], "PRIVATE KEY") {
			return fail(errors.New("crypto/tls: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have been switched"))
		} else {
			return fail(fmt.Errorf("crypto/tls: failed to find \"CERTIFICATE\" PEM block in certificate input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
		}
	}

	skippedBlockTypes = skippedBlockTypes[:0]
	var keyDERBlock *pem.Block
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			if len(skippedBlockTypes) == 0 {
				return fail(errors.New("crypto/tls: failed to find any PEM data in key input"))
			} else if len(skippedBlockTypes) == 1 && skippedBlockTypes[0] == "CERTIFICATE" {
				return fail(errors.New("crypto/tls: found a certificate rather than a key in the PEM for the private key"))
			} else {
				return fail(fmt.Errorf("crypto/tls: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
			}
		}
		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
		skippedBlockTypes = append(skippedBlockTypes, keyDERBlock.Type)
	}

	var err error
	switch keyDERBlock.Type {
	case "RSA PRIVATE KEY":
		cert.PrivateKey, err = parsePrivateKey(keyDERBlock.Bytes)
		if err != nil {
			eng := Sobj_Init()
			cert.PrivateKey, err = eng.Sobj_Loadkey(keyfile)
			if err != nil {
				return fail(err)
			}
		}
	case "EC PRIVATE KEY":
		eng := Sobj_Init()
		cert.PrivateKey, err = eng.Sobj_LoadECkey(keyfile)
		if err != nil {
			return fail(err)
		}
	default:
		fmt.Println("Unsupported key type: ", keyDERBlock.Type)

	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fail(err)
	}

	switch pub := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if keyPubKey, ok := cert.PrivateKey.(crypto.Signer).Public().(*rsa.PublicKey); ok {
			if pub.E != keyPubKey.E || pub.N.Cmp(keyPubKey.N) != 0 {
				return fail(errors.New("public key does not match"))
			}

			h := []byte{45, 113, 22, 66, 183, 38, 176, 68, 1, 98, 124, 169, 251, 172, 50, 245, 200, 83, 15, 177, 144, 60, 196, 219, 2, 37, 135, 23, 146, 26, 72, 129}
			s, err := cert.PrivateKey.(crypto.Signer).Sign(rand.Reader, h, crypto.SHA256)
			if err != nil {
				return fail(err)
			}
			err = rsa.VerifyPKCS1v15(x509Cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, h, s)
			if err != nil {
				return fail(err)
			}
		} else {
			return fail(errors.New("key type does not match"))
		}
	case *ecdsa.PublicKey:
		//EC Key, TBD.
		//h := []byte{45, 113, 22, 66, 183, 38, 176, 68, 1, 98, 124, 169, 251, 172, 50, 245, 200, 83, 15, 177, 144, 60, 196, 219, 2, 37, 135, 23, 146, 26, 72, 129}
		//s, err := cert.PrivateKey.(crypto.Signer).Sign(rand.Reader, h, crypto.SHA256)
	default:
		return fail(errors.New("unknown public key algorithm"))
	}

	return cert, nil
}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("tls: failed to parse private key")
}
