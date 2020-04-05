#!/usr/bin/env bash

pushd hacl-star/dist/gcc64-only
rm libevercrypt.a
make OPENSSL_HOME=/usr/include/openssl
mkdir -p decomposed_lib
pushd decomposed_lib
ar x ../libevercrypt.a

# remove unnecessary objects
rm aes-x86_64-linux.o
rm curve25519-x86_64-linux.o
rm EverCrypt_Cipher.o
rm EverCrypt_CTR.o
rm EverCrypt_Curve25519.o
rm EverCrypt_DRBG.o
rm EverCrypt_Ed25519.o
rm EverCrypt_Error.o
rm EverCrypt_Hash.o
rm EverCrypt_HKDF.o
rm EverCrypt_HMAC.o
rm EverCrypt.o
rm evercrypt_openssl.o
rm EverCrypt_Poly1305.o
rm EverCrypt_StaticConfig.o
rm EverCrypt_Vale.o
rm evercrypt_vale_stubs.o
rm Hacl_AES.o
rm Hacl_Chacha20_Vec32.o
rm Hacl_Curve25519_51.o
rm Hacl_Curve25519_64.o
rm Hacl_Curve25519_64_Slow.o
rm Hacl_Ed25519.o
rm Hacl_Frodo_KEM.o
rm Hacl_Hash.o
rm Hacl_HKDF.o
rm Hacl_HMAC_DRBG.o
rm Hacl_HMAC.o
rm Hacl_Kremlib.o
rm Hacl_NaCl.o
rm Hacl_Salsa20.o
rm Hacl_SHA3.o
rm Hacl_Spec.o
rm Lib_Memzero.o
rm Lib_PrintBuffer.o
rm Lib_RandomBuffer_System.o
rm MerkleTree.o
rm oldaesgcm-x86_64-linux.o
rm poly1305-x86_64-linux.o
rm sha256-x86_64-linux.o
rm Vale.o

rm ../libevercrypt.a
ar rv ../libevercrypt.a *.o
popd # decomposed_lib
rm -rf decomposed_lib
popd # gcc64-only
