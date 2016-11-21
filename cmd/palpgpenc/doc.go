/*
palpgpenc is a helper utilty to help generate pgp-encrypted secrets.

This is required because we want to encrypt labels of the secrets together with
the secrets themselves in order to verify the labels later in the decryption phase.

For possible flags and usage information, please see:
	palpgpenc -h
*/
package main
