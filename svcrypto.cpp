///////////////////////////////////////////////////////////////////////////////
//
// SUVA version 3
// Copyright (C) 2001-2012 ClearCenter
//
///////////////////////////////////////////////////////////////////////////////
//
// This project uses OpenSSL (http://openssl.org) for RSA, PEM, AES, RNG, DSO,
// and MD5 support.
//
///////////////////////////////////////////////////////////////////////////////
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but 
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program; if not, write to the Free Software Foundation, Inc.,
// 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
//
///////////////////////////////////////////////////////////////////////////////

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <iostream>
#include <stdexcept>
#include <sstream>
#include <map>
#include <vector>

#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <expat.h>
#include <pthread.h>

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#include <sys/time.h>

#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>
#ifndef OPENSSL_THREADS
#error "OpenSSL missing thread support"
#endif
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

#include "svoutput.h"
#include "svobject.h"
#include "svconf.h"
#include "svcrypto.h"
#include "svpacket.h"

#ifndef __ANDROID__
extern int errno;
#endif

pthread_mutex_t **svCrypto::mutex_crypto = NULL;

static void sv_crypto_lock(int mode, int n, const char *file, int line)
{
	if (svCrypto::mutex_crypto == NULL) {
		svError("%s: mutex_crypto not initialized!", __func__);
		// TODO: throw...
		return;
	}

	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(svCrypto::mutex_crypto[n]);
	else
		pthread_mutex_unlock(svCrypto::mutex_crypto[n]);
}

svCrypto::svCrypto(svAESKeySize aes_key_size)
	: svObject("svCrypto"), aes_key_bytes(0),
	max_payload_size(_SUVA_MAX_PAYLOAD),
	rsa_public_key(NULL), rsa_private_key(NULL),
	h_urandom(NULL)
{
	SetAESKeySize(aes_key_size);
}

svCrypto::svCrypto(uint32_t aes_key_size)
	: svObject("svCrypto"), aes_key_bytes(0),
	max_payload_size(_SUVA_MAX_PAYLOAD),
	rsa_public_key(NULL), rsa_private_key(NULL),
	h_urandom(NULL)
{
	SetAESKeySize(aes_key_size);
}

svCrypto::~svCrypto()
{
	if (rsa_public_key) RSA_free(rsa_public_key);
	if (rsa_private_key) RSA_free(rsa_private_key);
	if (h_urandom != NULL) fclose(h_urandom);
}

void svCrypto::Initialize(void)
{
	if (mutex_crypto) return;
	int num_locks = CRYPTO_num_locks();
	if (num_locks <= 0) return;

	mutex_crypto = new pthread_mutex_t *[num_locks];
	for (int i = 0; i < num_locks; i++) {
		mutex_crypto[i] = new pthread_mutex_t;
		pthread_mutex_init(mutex_crypto[i], NULL);
	}
	CRYPTO_set_locking_callback(sv_crypto_lock);
	svDebug("svCrypto: Initialized %d lock(s)\n", num_locks);
}

void svCrypto::Uninitialize(void)
{
	if (!mutex_crypto) return;
	int num_locks = CRYPTO_num_locks();
	if (num_locks <= 0) return;

	for (int i = 0; i < num_locks; i++) {
		pthread_mutex_destroy(mutex_crypto[i]);
		delete mutex_crypto[i];
	}

	delete mutex_crypto;
	mutex_crypto = NULL;
}

void svCrypto::SetAESKeySize(uint32_t aes_key_size)
{
	svAESKeySize key_size = svKS_AES_NULL;

	switch (aes_key_size) {
	case 128:
		key_size = svKS_AES_128;
		aes_key_bits = 128;
		break;
	case 192:
		key_size = svKS_AES_192;
		aes_key_bits = 192;
		break;
	case 256:
		key_size = svKS_AES_256;
		aes_key_bits = 256;
		break;
	default:
		throw svExCryptoInvalidKeySize("Invalid AES key size: " + aes_key_size);
	}

	SetAESKeySize(key_size);
}

void svCrypto::SetAESKeySize(svAESKeySize aes_key_size)
{
	this->aes_key_size = svKS_AES_NULL;

	switch (aes_key_size) {
	case svKS_AES_128:
		aes_key_bits = 128;
		this->aes_key_size = aes_key_size;
		break;
	case svKS_AES_192:
		aes_key_bits = 192;
		this->aes_key_size = aes_key_size;
		break;
	case svKS_AES_256:
		aes_key_bits = 256;
		this->aes_key_size = aes_key_size;
		break;
	default:
		throw svExCryptoInvalidKeySize("Invalid AES key size");
	}

	aes_key_bytes = aes_key_bits / 8;
	memset(aes_key, 0, _SUVA_MAX_AES_KEY_SIZE);

	if (_SUVA_MAX_PAYLOAD % aes_key_bits == 0)
		max_payload_size = _SUVA_MAX_PAYLOAD;
	else {
		max_payload_size =
			_SUVA_MAX_PAYLOAD - (_SUVA_MAX_PAYLOAD % aes_key_bits);
	}

	//svDebug("%s: AES key size: %d bits, max. packet length: %d",
	//	name.c_str(), aes_key_bits, max_payload_size);
}

int svCrypto::GatherRandomBytes(uint8_t *buffer, int length)
{
	if (RAND_bytes(buffer, length) == 1) return 1;
	if (RAND_pseudo_bytes(buffer, length) == 1) return 1;
#ifndef __WIN32__
	if (h_urandom == NULL)
		h_urandom = fopen("/dev/urandom", "r");
	if (h_urandom != NULL) {
		if (fread((void *)buffer, 1, length, h_urandom) != (size_t)length)
			return 0;
	}
	else return 0;
#else
	return 0;
#endif
	return 1;
}

void svCrypto::GenerateAESKey(void)
{
	memset(aes_key, 0, _SUVA_MAX_AES_KEY_SIZE);
	if (GatherRandomBytes(aes_key, aes_key_bytes) == 0)
		throw svExCryptoRandBytes();
	SetAESKey(svAES_ENCRYPT, aes_key, aes_key_encrypt);
	SetAESKey(svAES_DECRYPT, aes_key, aes_key_decrypt);
}

uint8_t *svCrypto::DuplicateAESKey(void)
{
	uint8_t *key = new uint8_t[aes_key_bytes];
	memcpy(key, aes_key, aes_key_bytes);
	return key;
}

void svCrypto::SetAESKey(svAESCrypt mode,
	const uint8_t *plain_key, AES_KEY &crypt_key)
{
	switch (mode) {
	case svAES_ENCRYPT:
		if (AES_set_encrypt_key(plain_key, aes_key_bits, &crypt_key) != 0)
			throw svExCryptoSetAESEncryptKey();
		break;

	case svAES_DECRYPT:
		if (AES_set_decrypt_key(plain_key, aes_key_bits, &crypt_key) != 0)
			throw svExCryptoSetAESDecryptKey();
		break;
	}
}

void svCrypto::SetAESKey(svAESCrypt mode, const uint8_t *plain_key)
{
	switch (mode) {
	case svAES_ENCRYPT:
		SetAESKey(mode, plain_key, aes_key_encrypt);
		break;
	case svAES_DECRYPT:
		SetAESKey(mode, plain_key, aes_key_decrypt);
		break;
	}
}

void svCrypto::AESCrypt(svAESCrypt mode, AES_KEY &key, uint8_t *src,
	uint32_t length, uint8_t *dst)
{
	uint8_t *ptr_src = src, *ptr_dst = dst;

	switch (mode) {
	case svAES_ENCRYPT:
		for (uint32_t i = 0; i < length; i += AES_BLOCK_SIZE)
			AES_encrypt(ptr_src + i, ptr_dst + i, &key);
		break;

	case svAES_DECRYPT:
		for (uint32_t i = 0; i < length; i += AES_BLOCK_SIZE)
			AES_decrypt(ptr_src + i, ptr_dst + i, &key);
		break;
	}
}

void svCrypto::AESCryptPacket(svAESCrypt mode, svPacket &pkt)
{
	uint32_t length = pkt.GetPayloadLength();
	uint8_t *payload = pkt.GetPayload();

	switch (mode) {
	case svAES_ENCRYPT:
		if (length % aes_key_bits) {
			pkt.SetPad((uint8_t)
				(aes_key_bits - (length % aes_key_bits)));
			GatherRandomBytes(payload + length, (uint32_t)pkt.GetPad());
			length += (uint32_t)pkt.GetPad();
			pkt.SetPayloadLength((uint16_t)length);
		}
		else pkt.SetPad(0);
		AESCrypt(mode, aes_key_encrypt, payload, length, payload);
		break;

	case svAES_DECRYPT:
		AESCrypt(mode, aes_key_decrypt, payload, length, payload);
		pkt.SetPayloadLength(pkt.GetPayloadLength() - pkt.GetPad());
		break;
	}
}

uint32_t svCrypto::RSACrypt(svRSACrypt mode, uint8_t *src,
	uint32_t length, uint8_t *dst)
{
	int rc = 0;
	switch (mode) {
	case svRSA_PUBLIC_ENCRYPT:
		if ((rc = RSA_public_encrypt(length, src, dst, rsa_public_key,
			RSA_PKCS1_OAEP_PADDING)) == -1)
			throw svExCryptoPublicRSAEncrypt();
		break;

	case svRSA_PRIVATE_DECRYPT:
		if ((rc = RSA_private_decrypt(length, src, dst, rsa_private_key,
			RSA_PKCS1_OAEP_PADDING)) == -1)
			throw svExCryptoPrivateRSADecrypt();
		break;
	}
	return (uint32_t)rc;
}

void svCrypto::SetHostKey(const char *hostkey)
{
	uint32_t i, j, byte;

	for (i = 0, j = 0; i < _SUVA_MAX_HOSTKEY_LEN; i += 2, j++) {
		if (sscanf(hostkey + i, "%2x", &byte) != 1)
			throw svExCryptoHostKeyParseError();
		this->hostkey[j] = (uint8_t)byte;
	}
}

svRSAKey::svRSAKey(const string &pem)
	: svObject("svRSAKey"), type(svRSA_TYPE_NULL), key(NULL), mtime(0)
{
	struct stat key_stat;
	if (stat(pem.c_str(), &key_stat) == -1)
		throw svExRSAKeyStat(pem, strerror(errno));
	mtime = key_stat.st_mtime;

	FILE *h_key = fopen(pem.c_str(), "r");
	if (!h_key) throw svExRSAKeyOpen(pem, strerror(errno));

	if ((key = PEM_read_RSA_PUBKEY(h_key, NULL, NULL, NULL)))
		type = svRSA_TYPE_PUBLIC;
	else {
		rewind(h_key);

		if ((key = PEM_read_RSAPrivateKey(h_key, NULL, NULL, NULL)))
			type = svRSA_TYPE_PRIVATE;
		else {
			ERR_load_crypto_strings();
			svError("%s: %s: %s", name.c_str(), pem.c_str(),
				ERR_error_string(ERR_get_error(), NULL));
		}
	}

	fclose(h_key);

	if (type == svRSA_TYPE_NULL) throw svExRSAKeyInvalid(pem);
	name = pem;
}

svRSAKey::~svRSAKey()
{
	if (key) RSA_free(key);
}

uint32_t svRSAKey::GetBits(void)
{
	return BN_num_bits(key->n);
}

RSA *svRSAKey::Duplicate(void)
{
	if (type == svRSA_TYPE_PUBLIC)
		return RSAPublicKey_dup(key);
	else if (type == svRSA_TYPE_PRIVATE)
		return RSAPrivateKey_dup(key);
	return NULL;
}

svHostKey::svHostKey()
	: svObject("svHostKey"), age(0) { };

svHostKey::svHostKey(const string &key, time_t age)
	: svObject("svHostKey"), key(key), age(age) { };

bool svHostKey::HasExpired(uint32_t key_ttl)
{
	if (time(NULL) >= time_t(age + key_ttl)) return true;
	return false;
}

svPublicRSAKey::svPublicRSAKey(RSA *key)
	: svObject("svPublicRSAKey"), key(key)
{
	gettimeofday(&tv, NULL);
}

svPublicRSAKey::~svPublicRSAKey()
{
	if (key) RSA_free(key);
}

bool svPublicRSAKey::HasExpired(uint32_t key_ttl)
{
	struct timeval tv_now;
	gettimeofday(&tv_now, NULL);
	if (uint32_t(tv_now.tv_sec - tv.tv_sec) > key_ttl) return true;
	return false;
}

// vi: ts=4
