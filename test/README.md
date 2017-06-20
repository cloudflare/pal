Integration Test
================

This integration test largely mirrors the steps taken by the demo in the `demo`
directory, except that everything is dockerized and automated. The steps are:
* Create the docker containers from `docker-compose.yaml` and the various
  `Dockerfile`s and create the `tmp` directory.
* Launch the `redoctober` container.
* Initialize an admin account and a number of user accounts in Red October.
* Encrypt two secrets in Red October, requiring delegation by 2 of 2 user
  accounts. Place the resulting ciphertexts in `tmp/pal_secrets.yaml`
* Launch the `pald` container.
* Delegate the two secrets for an account owned by the machine running `pald`.
* Run the `pal` container, which requests decryptions of the secrets in
  `tmp/pal_secrets.yaml` and verifies that the correct plaintexts are returned.
* Kill and remove the docker containers and remove the `tmp` directory.

# Assets
In order to make iteration easy, the only assets that are baked into the docker
images (via the `COPY` `Dockerfile` directive) are those that are unlikely to
change frequently, if at all. Currently, these are:
* `config.yaml` in the `pald` container
* `verify-plaintext.sh` in the `pal` container

All other assets are shared through runtime-mounted volumes so that they can be
changed without requiring the docker images to be re-built (which is very slow).
Currently, these are:
* All containers have the repository root's `bin` directory (containing the
  `pal`, `pald`, and `redoctober` binaries) mounted at `/testbin`.
* The `pald` and `redoctober` containers have `test/certs` mounted at `/certs`.

# Inter-Container Communication
Two methods of inter-container communication exist:
* The `redoctober` and `pald` containers share a private network so that `pald`
  can issue decryption requests to `redoctober`.
* The `pal` and `pald` containers share a volume at `/var/run` so that `pal`
  can access the unix domain socket used to communicate with `pald`.
