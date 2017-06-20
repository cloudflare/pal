## PAL

PAL is Cloudflare's container secret bootstrapping tool. This folder contains a
minimal demo to demonstrate how to use PAL with Red October.

PAL consists of:

* the `pal` program, which can be used as an entry point for a Docker container.
* the `pald` program, which runs on the host, does container label validation
  and se cret decryption.

### Demo preparation

This demo requires both Red October and PAL to be installed and in the user
path. It also requires a dummy program called `demo` that listens on port `9090`
returns secrets provided by PAL.

Building Red October and PAL requires a [working Go 1.6+
installation](http://golang.org/doc/install) and a properly set `GOPATH`.

```
$ go get -u github.com/cloudflare/redoctober
$ go get -u github.com/cloudflare/pal/pald
$ go get -u github.com/cloudflare/pal/pal
$ go get -u github.com/cloudflare/pal/demo
```

will download and build the redoctober and pal sources, installing `redoctober`,
`pal`, `pald`, and `demo` into `$GOPATH/bin/`.

### Running the Demo

The demo is organized into a series of bash scripts. They can be run
sequentially to demonstrate how all the pieces fit together. These scripts need
to be run from the same directory as the this README.

* `0-setup.sh`: Set up a working directory for the demo and ensure that all
  dependencies are installed.
* `1-start-ro.sh`: Start a Red October server listening on `localhost:8080` and
  create three accounts - one for `pald` and two for secret owners.
* `2-encrypt-secret.sh`: Take two secrets, encrypt them with Red October with
  the two owner accounts, and embed the ciphertexts in a PAL secret YAML file -
  one as a file secret and one as an environment variable secret for the `demo`
  environment. Save this as `pal_secrets.yaml`.
* `3-start-pald.sh`: Start `pald`, listening on the unix socket
  `tmp/sock/pald.sock` with configuration `config.yaml` and environment `demo`
  in order to select the set secrets.
* `4-delegate-authorization.sh`: Each of the two owners delegates the ability
  for the `pald` account to decrypt the secret 10 times in the next hour.
* `5-run-pal.sh`: Run `pal` configured to use the socket created in step 2. This
  makes a request to `pald` for the ciphertexts to be decrypted, and installs
  the resulting plaintexts. `pal` then executes `demo`.
* `6-query-demo.sh`: Send an HTTP request to the toy `demo` server to verify
  that the secrets were decrypted and available.
* `7-cleanup.sh`: Kill all the previously-started processes and clean up the
  `tmp` directory.

### Testing with Docker

If you want to test this demo with Docker, instead of running script 5 directly,
build and run a Docker container containing `demo` with the entrypoint set to
`5-run-pal.sh`. A more involved example of a docker-based setup can be seen in
the integration test in the `test` directory (in the repository root).
