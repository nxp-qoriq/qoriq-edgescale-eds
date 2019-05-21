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

enum sk_status_code sk_its(char *its)
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
    sprintf(its, "%.8x", *((int *)(ptr + 0x200)));

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
	"os"
	"strings"
	"unsafe"
)

func GetPlatform() string {
	fd, err := os.Open("/proc/device-tree/compatible")
	if err != nil {
		return ""
	}
	var d = make([]byte, 100)
	n, _ := fd.Read(d)
	platform := strings.Split(string(d[:n]), ",")
	if len(platform) > 1 {
		return platform[1]
	}
	return ""

}

func SK_ITS() bool {
	if strings.HasPrefix(GetPlatform(), "ls") {
		c_its := C.CString("00000000")
		C.sk_its(c_its)
		defer C.free(unsafe.Pointer(c_its))
		its := C.GoString(c_its)
		if its[1] == '4' {
			return true
		}
	}
	return false
}
