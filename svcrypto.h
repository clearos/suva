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

#ifndef _SVCRYPTO_H
#define _SVCRYPTO_H

enum svAESKeySize
{
	svKS_AES_NULL,
	svKS_AES_128,
	svKS_AES_192,
	svKS_AES_256
};

enum svAESCrypt
{
	svAES_ENCRYPT,
	svAES_DECRYPT
};

enum svRSACrypt
{
	svRSA_PUBLIC_ENCRYPT,
	svRSA_PRIVATE_DECRYPT,
};

enum svRSAKeyType
{
	svRSA_TYPE_NULL,
	svRSA_TYPE_PUBLIC,
	svRSA_TYPE_PRIVATE,
};

#define _SUVA_MAX_AES_KEY_SIZE	256

class svExCryptoInvalidKeySize : public runtime_error
{
public:
	explicit svExCryptoInvalidKeySize(const string &what)
		: runtime_error(what) { };
	virtual ~svExCryptoInvalidKeySize() throw() { };
};

class svExCryptoRandBytes : public runtime_error
{
public:
	explicit svExCryptoRandBytes()
		: runtime_error("Error gathering random bytes") { };
	virtual ~svExCryptoRandBytes() throw() { };
};

class svExCryptoPublicRSAEncrypt : public runtime_error
{
public:
	explicit svExCryptoPublicRSAEncrypt()
		: runtime_error("Public RSA encryption failed") { };
	virtual ~svExCryptoPublicRSAEncrypt() throw() { };
};

class svExCryptoPrivateRSADecrypt : public runtime_error
{
public:
	explicit svExCryptoPrivateRSADecrypt()
		: runtime_error("Private RSA decryption failed") { };
	virtual ~svExCryptoPrivateRSADecrypt() throw() { };
};

class svExCryptoSetAESEncryptKey : public runtime_error
{
public:
	explicit svExCryptoSetAESEncryptKey()
		: runtime_error("Error setting AES encrypt key") { };
	virtual ~svExCryptoSetAESEncryptKey() throw() { };
};

class svExCryptoSetAESDecryptKey : public runtime_error
{
public:
	explicit svExCryptoSetAESDecryptKey()
		: runtime_error("Error setting AES decrypt key") { };
	virtual ~svExCryptoSetAESDecryptKey() throw() { };
};

class svExCryptoHostKeyParseError : public runtime_error
{
public:
	explicit svExCryptoHostKeyParseError()
		: runtime_error("Error parsing host key") { };
	virtual ~svExCryptoHostKeyParseError() throw() { };
};

class svPacket;
class svCrypto : public svObject
{
public:
	svCrypto(uint32_t aes_key_size);
	svCrypto(svAESKeySize aes_key_size);
	virtual ~svCrypto();

	static void Initialize(void);
	static void Uninitialize(void);

	void SetAESKeySize(uint32_t aes_key_size);
	void SetAESKeySize(svAESKeySize aes_key_size);

	void SetAESKey(svAESCrypt mode,
		const uint8_t *plain_key, AES_KEY &crypt_key);
	void SetAESKey(svAESCrypt mode, const uint8_t *plain_key);

	uint8_t *DuplicateAESKey(void);

	svAESKeySize GetAESKeySize(void) { return aes_key_size; };
	uint32_t GetAESKeyBits(void) { return aes_key_bits; };
	uint32_t GetAESKeyBytes(void) { return aes_key_bytes; };

	int GatherRandomBytes(uint8_t *buffer, int length);

	void GenerateAESKey(void);
	uint8_t *GetAESRawKey(void) { return aes_key; };
	AES_KEY *GetAESKey(svAESCrypt mode)
	{
		switch (mode) {
		case svAES_ENCRYPT:
			return &aes_key_encrypt;
		case svAES_DECRYPT:
			return &aes_key_decrypt;
		}
		return NULL;
	};

	void AESCrypt(svAESCrypt mode, AES_KEY &key, uint8_t *src,
		uint32_t length, uint8_t *dst);
	void AESCryptPacket(svAESCrypt mode, svPacket &pkt);

	void SetRSAPublicKey(RSA *key)
	{
		if (rsa_public_key) RSA_free(rsa_public_key);
		rsa_public_key = key;
	};
	void SetRSAPrivateKey(RSA *key)
	{ 
		if (rsa_private_key) RSA_free(rsa_private_key);
		rsa_private_key = key;
	};
	RSA *GetRSAPublicKey(void) { return rsa_public_key; };
	RSA *GetRSAPrivateKey(void) { return rsa_private_key; };
	uint32_t GetRSAPublicKeySize(void)
	{
		if (!rsa_public_key) return 0;
		return RSA_size(rsa_public_key);
	};
	uint32_t GetRSAPrivateKeySize(void)
	{
		if (!rsa_private_key) return 0;
		return RSA_size(rsa_private_key);
	};
	uint32_t RSACrypt(svRSACrypt mode, uint8_t *src, uint32_t length,
		uint8_t *dst);

	void SetHostKey(const char *hostkey);
	uint8_t *GetHostKey(void) { return hostkey; };

	uint32_t GetMaxPayloadSize(void) { return max_payload_size; };

	static pthread_mutex_t **mutex_crypto;

protected:
	uint8_t aes_key[_SUVA_MAX_AES_KEY_SIZE / 8];
	AES_KEY aes_key_encrypt;
	AES_KEY aes_key_decrypt;
	svAESKeySize aes_key_size;
	uint32_t aes_key_bits;
	uint32_t aes_key_bytes;
	uint32_t max_payload_size;

	RSA *rsa_public_key;
	RSA *rsa_private_key;

	uint8_t hostkey[_SUVA_MAX_HOSTKEY_LEN];

	FILE *h_urandom;
};

class svExRSAKeyStat : public runtime_error
{
public:
	explicit svExRSAKeyStat(const string &pem, const string &what)
		: runtime_error(pem + ": " + what) { };
	virtual ~svExRSAKeyStat() throw() { };
};

class svExRSAKeyOpen : public runtime_error
{
public:
	explicit svExRSAKeyOpen(const string &pem, const string &what)
		: runtime_error(pem + ": " + what) { };
	virtual ~svExRSAKeyOpen() throw() { };
};

class svExRSAKeyInvalid : public runtime_error
{
public:
	explicit svExRSAKeyInvalid(const string &pem)
		: runtime_error(pem) { };
	virtual ~svExRSAKeyInvalid() throw() { };
};

class svRSAKey : public svObject
{
public:
	svRSAKey(const string &pem);
	~svRSAKey();

	RSA *Get(void) { return key; };
	svRSAKeyType GetType(void) { return type; };
	time_t GetLastModified(void) { return mtime; };
	uint32_t GetBits(void);
	RSA *Duplicate(void);

protected:
	svRSAKeyType type;
	RSA *key;
	time_t mtime;
};

class svHostKey : public svObject
{
public:
	svHostKey();
	svHostKey(const string &key, time_t age = 0);

	const string &GetKey(void) const { return key; };
	time_t GetAge(void) const { return age; };

	void SetKey(const string &key) { this->key = key; };
	void AssignKey(const char *key)
	{
		this->key.assign(key, _SUVA_MAX_HOSTKEY_LEN);
	};
	void SetAge(time_t age) { this->age = age; };

	bool HasExpired(uint32_t key_ttl);

protected:
	string key;
	time_t age;
};

class svPublicRSAKey : public svObject
{
public:
	svPublicRSAKey(RSA *key);
	virtual ~svPublicRSAKey();

	bool HasExpired(uint32_t key_ttl);
	RSA *GetKey(void) { return key; };

protected:
	RSA *key;
	struct timeval tv;
};

#endif // _SVCRYPTO_H
// vi: ts=4
