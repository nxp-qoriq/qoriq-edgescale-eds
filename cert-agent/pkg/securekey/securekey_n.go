// +build !secure

/*
 **********************************
 *
 * Copyright 2018 NXP
 *
 **********************************
 */

package sk

// Not implemented. Reserved for future use.
func SK_fuid() (string, error) {
	return "", nil
}

// Not implemented. Reserved for future use.
func SK_oemid() (string, error) {
	return "", nil
}

// Not implemented. Reserved for future use.
func SK_sign(msg string) (string, error) {
	return "", nil
}

// Not implemented. Reserved for future use.
func SKPubKeySha1() (string, error) {
	return "", nil
}
