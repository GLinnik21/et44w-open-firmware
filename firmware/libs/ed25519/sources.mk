# The Monocypher files the ed25519 lib builds, relative to the Monocypher checkout: only the optional Ed25519 file
# (RFC 8032 with SHA-512) and the core it builds on. Shared by lib.mk and the host tests (libs/ota/test).
ED25519_SRC := src/monocypher.c src/optional/monocypher-ed25519.c
ED25519_INC := src src/optional
