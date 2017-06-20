/*
pald is the daemon running on the host responsible for decrypting secrets. It
listens on a unix socket which should be bind-mounted into any container
wishing to decrypt secrets with pald.
pald is configured using an yaml file. The configurations are separated by their environments.
Possible configurations are:
	- roserver: address of the redoctober server. Required if we need to decrypt RedOctober secrets
	- ca: location of the certificates to communicate with RedOctober.
	- ro_user: RedOctober username.
	- ro_password: RedOctober password.
	- pgp_keyring_path: path to the pgp secret keyring to decrypt pgp encrypted secrets.
	- pgp_passphrase: passphrase to decrypt the keyring if required.
	- pgp_cipher: pgp chosen cipher.
	- pgp_hash: pgp chosen hash.
	- labels_enabled: whether to enable trusted label checking.
	- labels_retriever: use notary to trusted label checking. This is the only available scheme now.
	- notary_trust_server: notary server to retrieve the trusted digest.
	- notary_trust_dir: path to the directory for storing notary trust data.
Example configuration:
	dev:
		roserver: redoctober.local:8080
		ca: /tmp/server.crt
		ro_user: Alice
		ro_password: Lewis
		labels_enabled: false
	prod:
		roserver: redoctober.prod
		ca: /tmp/server.crt
		ro_user: James
		ro_password: Bond
		pgp_keyring_path: /etc/pal/keyrings/secring.gpg
		pgp_passphrase: paltest
		pgp_cipher: aes256
		pgp_hash: sha256
		labels_enabled: true
		labels_retriever: docker
		notary_trust_server: https://notary.docker.io
		notary_trust_dir: .trust
Example usage:
	pald -addr=unix:///var/run/pald.sock -config=/etc/pal/config.yaml -env=prod
For possible flags and usage information, please see:
	pald -h
*/
package main
