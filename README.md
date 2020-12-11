# Overview

This repository contains sample implementations for creating a valid ciphertext which will decrypt under two different keys for *AES-GCM*, *AES-GCM-SIV* and *AES-OCB3*. For more details on this see our paper ["How to Abuse and Fix Authenticated Encryption Without Key Commitment"](https://eprint.iacr.org/2020/1456).

The implementations require [Sagemath](https://www.sagemath.org/) and the GCM and OCB implementations require [PyCryptodome](https://www.pycryptodome.org/en/latest/).

The `mitra_*` versions of the script can be used to take polyglots generated with https://github.com/corkami/mitra as input.
