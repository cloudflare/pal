
/*
pal is a client program you can use as your Docker entrypoint to communicate
with pald daemon on the host. By using a bind-mounted unix socket, it sends the
ciphertext of of any required secrets then setup the decrypted secrets
either as environment variables or files inside the container, then
execute the specified process.
Example usage:
	export PAL_SECRETS_YAML=$(cat << EOF
	dev:
		env:
			RO_VAR: ro:redoctober encrypted blob
			PGP_VAR: pgp:pgp encrypted blob
	prod:
		env:
			RO_VAR: ro:production redoctober encrypted blob
			PGP_VAR: pgp:production pgp encrypted blob
	EOF
	pal -socket=/var/run/pald.sock -env=prod -- env
For possible flags and usage information, please see:
	pal -h
*/
package main
