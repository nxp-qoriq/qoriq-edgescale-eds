package sk

/*
#cgo LDFLAGS: -lsecure_obj -lteec
#include "securekey_mp.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"

#define DEBUG
#define     MP_TAG_LEN              32

bool C_sk_fuid(char *out) {
    uint8_t ret, i ;
    uint8_t fuid_len;
    uint8_t *fuid;

    fuid_len = sk_get_fuid_len();
    fuid = (uint8_t *)malloc(fuid_len);
    if (!fuid ) {
        printf("malloc failed\n");
        ret = -1;
        goto fuid_malloc_fail;;
    }

    if (sk_get_fuid(fuid)) {
        printf("sk_get_fuid failed\n");
        ret = -1;
        goto sk_get_fuid_fail;
    }

    for (i =0; i < fuid_len; i++){
        out += sprintf(out, "%02x", fuid[i]);
    }
    ret = 0;

sk_get_fuid_fail:
    free(fuid);
fuid_malloc_fail:
    return ret;
}

bool C_sk_sign(char *MSG, char *out) {
	int i = 0, ret = -1;
	uint8_t *temp, *temp1;
	enum sk_status_code ret_status;
	struct sk_EC_sig sign_req;
	struct sk_EC_point pub_key_req;
	uint8_t *mp_tag;
	uint8_t pub_key_len, digest_len, sig_len, mp_tag_len, msg_len;
	uint8_t *msg, *digest;

	ret_status = sk_lib_init();
	if (ret_status == SK_FAILURE) {
		printf("sk_lib_init failed\n");
		goto err;
	}

	mp_tag = (uint8_t *)malloc(MP_TAG_LEN);
	if (!mp_tag ) {
		printf("malloc failed\n");
        ret = -1;
		goto mp_tag_malloc_fail;;
	}

	memset((void *)mp_tag, 0, MP_TAG_LEN);

	if (sk_mp_get_mp_tag(mp_tag, MP_TAG_LEN)){
        ret = -1;
		goto sk_mp_get_mp_tag_fail;
	}

    for (i = 0; i < MP_TAG_LEN; i++){
        out += sprintf(out, "%02x", mp_tag[i]);
    }

	digest_len = sk_mp_get_digest_len();
	sig_len = sk_mp_get_sig_len();

	msg_len = strlen(MSG);

	temp1 = (uint8_t  *)malloc(msg_len + digest_len
			+ (2 * sig_len));
	if (!temp1) {
		printf("malloc failed\n");
		printf("templ failed\n");
        ret = -1;
		goto temp1_fail;
	}

	sign_req.len = sig_len;
	msg = temp1;
	digest = temp1 + msg_len;
	sign_req.r = digest + digest_len;
	sign_req.s = sign_req.r + sign_req.len;

	memcpy(msg, MSG, msg_len);

	ret_status = sk_mp_sign(msg, msg_len, &sign_req, digest, digest_len);
	if (ret_status) {
		printf("sk_mp_sign failed %d \n", ret_status);
        ret = -1;
		goto mp_sign_fail;
	}

    for (i = 0; i < sig_len; i++){
        out += sprintf(out, "%02x", *(sign_req.r + i));
    }

    for (i = 0; i < sig_len; i++){
        out += sprintf(out, "%02x", *(sign_req.s + i));
    }


	sk_lib_exit();
	ret = 0;

sk_mp_get_mp_tag_fail:
	free(mp_tag);
mp_tag_malloc_fail:
mp_sign_fail:
	free(temp1);
temp1_fail:
err:
	return ret;
}

*/
import "C"

import (
	"errors"
	"unsafe"
)

func SK_fuid() (string, error) {
	cfuid := C.CString("")
	defer C.free(unsafe.Pointer(cfuid))

	ret := C.C_sk_fuid(cfuid)

	if !ret {
		return C.GoString(cfuid), nil
	} else {
		return "", errors.New("FUID read failed")
	}
}

func SK_sign(msg string) (string, error) {
	cmsg := C.CString(msg)

	var val [128]byte
	csig := (*C.char)(unsafe.Pointer(&val[0]))

	defer C.free(unsafe.Pointer(cmsg))

	ret := C.C_sk_sign(cmsg, csig)

	if !ret {
		return C.GoString(csig), nil
	} else {
		return "", errors.New("sk_sign failed")
	}
}
