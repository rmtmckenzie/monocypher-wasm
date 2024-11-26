MONOCYPHER_VERSION = 4.0.2
PACKAGE_VERSION = 0
MONOCYPHER_VERSION_NAME = monocypher-${MONOCYPHER_VERSION}

COMPILE_FLAGS = -Wall \
	--target=wasm32 \
	-Os \
	-nostdlib \
	-fvisibility=hidden \
	-std=c11 \
	-ffunction-sections \
	-fdata-sections \
	-mbulk-memory \
	-DPRINTF_DISABLE_SUPPORT_FLOAT=1 \
	-DPRINTF_DISABLE_SUPPORT_LONG_LONG=1 \
	-DPRINTF_DISABLE_SUPPORT_PTRDIFF_T=1

.PHONY: all npm check test clean

all: npm monocypher.min.js
npm: test
	deno run -A scripts/build_npm.ts $(MONOCYPHER_VERSION)-$(PACKAGE_VERSION)

test: check monocypher_wasm.ts test-vectors.json.gz
	deno test --allow-read=test-vectors.json.gz

check:
	deno fmt
	deno lint

clean:
	rm -rf build buildNpmTest walloc.o monocypher.o

monocypher.min.js: mod.ts monocypher_wasm.ts Makefile
	deno run --allow-read --allow-write --allow-env --allow-net --allow-run scripts/bundle_mod.ts
	# > monocypher.min.js
	# deno bundle mod.ts | deno npm:esbuild --allow-end --minify > monocypher.min.js

monocypher_wasm.ts: monocypher.wasm scripts/wasm_to_ts.ts Makefile
	deno run scripts/wasm_to_ts.ts < monocypher.wasm > monocypher_wasm.ts

monocypher.wasm: monocypher.o walloc.o Makefile
	wasm-ld -o monocypher.wasm --no-entry --strip-all -error-limit=0 --no-entry --lto-O3 -O3 --gc-sections \
		--export malloc \
		--export free \
		--export crypto_verify16 \
		--export crypto_verify32 \
		--export crypto_verify64 \
		--export crypto_wipe \
		--export crypto_aead_lock \
		--export crypto_aead_unlock \
		--export crypto_aead_write \
		--export crypto_aead_read \
		--export crypto_blake2b \
		--export crypto_blake2b_keyed \
		--export crypto_blake2b_init \
		--export crypto_blake2b_keyed_init \
		--export crypto_blake2b_update \
		--export crypto_blake2b_final \
		--export crypto_argon2 \
		--export crypto_x25519_public_key \
		--export crypto_x25519 \
		--export crypto_x25519_to_eddsa \
		--export crypto_x25519_inverse \
		--export crypto_x25519_dirty_small \
		--export crypto_x25519_dirty_fast \
		--export crypto_eddsa_key_pair \
		--export crypto_eddsa_sign \
		--export crypto_eddsa_check \
		--export crypto_eddsa_to_x25519 \
		--export crypto_eddsa_trim_scalar \
		--export crypto_eddsa_reduce \
		--export crypto_eddsa_mul_add \
		--export crypto_chacha20_h \
		--export crypto_chacha20_djb \
		--export crypto_chacha20_ietf \
		--export crypto_chacha20_x \
		--export crypto_poly1305 \
		--export crypto_poly1305_init \
		--export crypto_poly1305_update \
		--export crypto_poly1305_final \
		--export crypto_elligator_map \
		--export crypto_elligator_rev \
		--export crypto_elligator_key_pair \
		--export crypto_blake2b_ctx_size \
		--export crypto_poly1305_ctx_size \
		monocypher.o walloc.o

walloc.o: walloc.c Makefile
	clang -c $(COMPILE_FLAGS) -o walloc.o walloc.c

monocypher.o: monocypher.c monocypher.h monocypher_extra.c Makefile
	clang -c $(COMPILE_FLAGS) -o monocypher.o monocypher_extra.c

monocypher_extra.o:

test-vectors.json.gz: vectors.h scripts/build_test_vectors.ts Makefile
	deno run scripts/build_test_vectors.ts < vectors.h > test-vectors.json.gz

# monocypher.c monocypher.h vectors.h &: Makefile
# 	curl https://monocypher.org/download/$(MONOCYPHER_VERSION_NAME).tar.gz | \
# 		tar -xzv --strip-components=2 \
# 		$(MONOCYPHER_VERSION_NAME)/src/monocypher.c \
# 		$(MONOCYPHER_VERSION_NAME)/src/monocypher.h \
# 		$(MONOCYPHER_VERSION_NAME)/tests/tis-ci-vectors.h
# 	mv tis-ci-vectors.h vectors.h
	# touch monocypher.c
	# touch monocypher.h
	# touch vectors.h
