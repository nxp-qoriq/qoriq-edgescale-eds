// +build !secure

/*
 **********************************
 *
 * Copyright 2018 NXP
 *
 **********************************
 */

package sk

/*
#include "stdio.h"
#include "stdint.h"
#include "stdlib.h"
#include "string.h"
#include "errno.h"
#include "unistd.h"
#include "fcntl.h"
#include "sys/mman.h"
#define SFP_BASE_ADDRESS    0x01E80000

enum sk_status_code
{
    SK_SUCCESS = 0,
    SK_FAILURE = -1,
};

enum sk_status_code sk_get_fuid(char *fuid)
{
    uint32_t ret = SK_FAILURE;
    int mem;
    void *ptr;

    if ((mem = open ("/dev/mem", O_RDWR | O_SYNC)) == -1) {
        printf("Cannot open /dev/mem\n");
        perror("open");
        ret = -errno;
        goto err;
    }

    ptr = mmap (0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, mem, SFP_BASE_ADDRESS);
    if(ptr == (void *) -1) {
        printf("Memory map failed.\n");
        perror("mmap");
        ret = -errno;
        goto err1;
    }

	ptr = ptr + 135*4;

    for (int i = 0; i < 8; i++){
        fuid += sprintf(fuid, "%02x", *((uint8_t*)ptr+i));
    }

    ret = SK_SUCCESS;
    munmap(ptr, 4096);
err1:
    close(mem);
err:
    return ret;
}

enum sk_status_code sk_get_oemid(char *oem_id)
{
    uint32_t ret = SK_FAILURE;
    int mem;
    void *ptr;

    if ((mem = open ("/dev/mem", O_RDWR | O_SYNC)) == -1) {
        printf("Cannot open /dev/mem\n");
        perror("open");
        ret = -errno;
        goto err;
    }

    ptr = mmap (0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, mem, SFP_BASE_ADDRESS);
    if(ptr == (void *) -1) {
        printf("Memory map failed.\n");
        perror("mmap");
        ret = -errno;
        goto err1;
    }

	ptr = ptr + 157*4;
	for (int i=0; i < 20; i++) {
        oem_id += sprintf(oem_id, "%02x", *((uint8_t*)ptr+i));
	}

    ret = SK_SUCCESS;
    munmap(ptr, 4096);
err1:
    close(mem);
err:
    return ret;
}

*/
import "C"

import (
	"strings"
	"unsafe"
)

func SK_fuid() (string, error) {
	if strings.HasPrefix(GetPlatform(), "ls") {
		c_fuid := C.CString("0000000000000000")
		defer C.free(unsafe.Pointer(c_fuid))
		C.sk_get_fuid(c_fuid)
		return C.GoString(c_fuid), nil
	}
	return "0000000000000000", nil
}

func SK_oemid() (string, error) {
	if strings.HasPrefix(GetPlatform(), "ls") {
		buf := "0000000000000000000000000000000000000000"
		c_oemid := C.CString(string(buf))

		defer C.free(unsafe.Pointer(c_oemid))
		C.sk_get_oemid(c_oemid)
		return C.GoString(c_oemid), nil
	}
	return "0000000000000000000000000000000000000000", nil
}

// Not implemented. Reserved for future use.
func SK_sign(msg string) (string, error) {
	return "", nil
}

// Not implemented. Reserved for future use.
func SKPubKeySha1() (string, error) {
	return "", nil
}
