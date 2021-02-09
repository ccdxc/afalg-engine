#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

#include <openssl/aes.h>
#include <openssl/engine.h>

#include "e_afalg.h"

struct cipher_data
{
	int tfmfd;
	int op;
	uint32_t iv_len;
	void *tag;
	uint32_t tag_len;
	void *aad;
	uint32_t aad_len;
	void *data;
};

#define CIPHER_DATA(ctx) ((struct cipher_data*)(ctx->cipher_data))

EVP_CIPHER *ciphers[6] = { };

/***** CBC ****************************************************************************/

static struct sockaddr_alg aes_cbc_sa = {
	.salg_family = AF_ALG,
	.salg_type = "skcipher",
	.salg_name = "cbc(aes)",
};

static int aes_cbc_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	struct cipher_data *cd = CIPHER_DATA(ctx);
	int key_len = EVP_CIPHER_CTX_key_length(ctx);

	cd->tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if(cd->tfmfd == -1)
		return 0;

	if (bind(cd->tfmfd, (struct sockaddr *)&aes_cbc_sa, sizeof(struct sockaddr_alg)) == -1)
		return 0;

	if (setsockopt(cd->tfmfd, SOL_ALG, ALG_SET_KEY, key, key_len) == -1)
		return 0;

	cd->op = accept(cd->tfmfd, NULL, 0);
	if(cd->op == -1)
		return 0;

	return 1;
}

static int aes_cbc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out_arg, const unsigned char *in_arg, size_t nbytes)
{
	struct cipher_data *cd = CIPHER_DATA(ctx);
	uint32_t op = ctx->encrypt ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT;
	int block_size = EVP_CIPHER_CTX_block_size(ctx);
	struct msghdr msg = {.msg_name = NULL};
	struct cmsghdr *cmsg;
	struct af_alg_iv *ivm;
	struct iovec iov;
	char buf[CMSG_SPACE(sizeof(op)) + CMSG_SPACE(offsetof(struct af_alg_iv, iv) + block_size)];
	ssize_t len;
	unsigned char save_iv[block_size];

	memset(buf, 0, sizeof(buf));

	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	memcpy(CMSG_DATA(cmsg), &op, 4);

	/* set IV - or update if it was set before */
	if (op == ALG_OP_DECRYPT)
		memcpy(save_iv, in_arg + nbytes - block_size, block_size);

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(offsetof(struct af_alg_iv, iv) + block_size);
	ivm = (void*)CMSG_DATA(cmsg);
	ivm->ivlen = block_size;
	memcpy(ivm->iv, ctx->iv, block_size);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	iov.iov_base = (void*)in_arg;
	iov.iov_len = nbytes;

	len = sendmsg(cd->op, &msg, 0);
	if (len == -1)
		return -1;

	if (read(cd->op, out_arg, len) != len)
		return -1;

	/* copy IV for next iteration */
	if (op == ALG_OP_ENCRYPT)
		memcpy(ctx->iv, out_arg + len - block_size, block_size);
	else
		memcpy(ctx->iv, save_iv, block_size);

	return len;
}

static int aes_cbc_cleanup(EVP_CIPHER_CTX *ctx)
{
	struct cipher_data *cd = CIPHER_DATA(ctx);
	if (cd->tfmfd != -1)
		close(cd->tfmfd);
	if (cd->op != -1)
		close(cd->op);
	return 1;
}

static EVP_CIPHER *aes_cbc_create(int nid, int key_len)
{
	EVP_CIPHER *cipher = OPENSSL_malloc(sizeof(EVP_CIPHER));
	if (cipher == NULL)
		return NULL;
	memset(cipher, 0, sizeof(EVP_CIPHER));

	cipher->nid = nid;
	cipher->block_size = AES_BLOCK_SIZE;
	cipher->key_len = key_len/8;
	cipher->iv_len = AES_BLOCK_SIZE;
	cipher->flags = EVP_CIPH_CBC_MODE;
	cipher->init = aes_cbc_init;
	cipher->do_cipher = aes_cbc_do_cipher;
	cipher->cleanup = aes_cbc_cleanup;
	cipher->ctx_size = sizeof(struct cipher_data);

	return cipher;
}

/***** GCM ****************************************************************************/

#define AES_GCM_MAX_TAG_LENGTH	16

static struct sockaddr_alg aes_gcm_sa = {
	.salg_family = AF_ALG,
	.salg_type = "aead",
	.salg_name = "gcm(aes)",
};

static int aes_gcm_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	struct cipher_data *cd = CIPHER_DATA(ctx);
	int key_len = EVP_CIPHER_CTX_key_length(ctx);

	if (cd->iv_len == 0)
		return 0;

	cd->tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (cd->tfmfd == -1)
		return 0;

	if (bind(cd->tfmfd, (struct sockaddr *)&aes_gcm_sa, sizeof(struct sockaddr_alg)) == -1)
		return 0;

	if (setsockopt(cd->tfmfd, SOL_ALG, ALG_SET_KEY, key, key_len) == -1)
		return 0;

	memcpy(ctx->iv, iv, cd->iv_len);
	if (cd->tag_len == 0)
		cd->tag_len = AES_GCM_MAX_TAG_LENGTH;

	return 1;
}

static int aes_gcm_do_cipher_enc(EVP_CIPHER_CTX *ctx, unsigned char *out_arg, const unsigned char *in_arg, size_t nbytes)
{
	struct cipher_data *cd = CIPHER_DATA(ctx);
	uint32_t op = ALG_OP_ENCRYPT;
	struct msghdr msg = {.msg_name = NULL};
	struct cmsghdr *cmsg;
	struct af_alg_iv *ivm;
	struct iovec iov[3];
	char buf[/*op*/CMSG_SPACE(4) + /*af_alg_iv*/CMSG_SPACE(offsetof(struct af_alg_iv, iv) + cd->iv_len) + /*aad_len*/CMSG_SPACE(4)];
	ssize_t len;

	/* EVP_EncryptUpdate(NULL, ...) - set AAD */
	if (out_arg == NULL) {
		/* Must be first EVP_EncryptUpdate() call */
		if (cd->data != NULL)
			return -1;
		/* Must be only EVP_EncryptUpdate(NULL) call */
		if (cd->aad != NULL)
			return -1;
		cd->aad_len = nbytes;
		cd->aad = OPENSSL_malloc(cd->aad_len);
		if (cd->aad == NULL)
			return -1;
		memcpy(cd->aad, in_arg, cd->aad_len);
		return cd->aad_len;
	}

	/* EVP_EncryptFinal_ex() */
	if (in_arg == NULL) {
		/* EVP_EncryptUpdate() should be called at least once */
		if (cd->data == NULL)
			return -1;
		return 0;
	}

	/* Single EVP_EncryptUpdate() only */
	if (cd->data != NULL)
		return -1;

	if (setsockopt(cd->tfmfd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, cd->tag_len) == -1)
		return -1;

	cd->op = accept(cd->tfmfd, NULL, 0);
	if (cd->op == -1)
		return -1;

	cd->data = OPENSSL_malloc(cd->aad_len + nbytes + cd->tag_len);
	if (cd->data == NULL)
		return -1;

	memset(buf, 0, sizeof(buf));

	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	memcpy(CMSG_DATA(cmsg), &op, 4);

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(offsetof(struct af_alg_iv, iv) + cd->iv_len);
	ivm = (void*)CMSG_DATA(cmsg);
	ivm->ivlen = cd->iv_len;
	memcpy(ivm->iv, ctx->iv, cd->iv_len);

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
	cmsg->cmsg_len = CMSG_LEN(4);
	memcpy(CMSG_DATA(cmsg), &cd->aad_len, 4);

	msg.msg_iov = iov;
	msg.msg_iovlen = 0;

	if (cd->aad_len != 0) {
		iov[msg.msg_iovlen].iov_base = cd->aad;
		iov[msg.msg_iovlen].iov_len = cd->aad_len;
		msg.msg_iovlen++;
	}

	iov[msg.msg_iovlen].iov_base = (void*)in_arg;
	iov[msg.msg_iovlen].iov_len = nbytes;
	msg.msg_iovlen++;

	len = sendmsg(cd->op, &msg, 0);
	if (len != cd->aad_len + nbytes)
		return -1;

	len = read(cd->op, cd->data, cd->aad_len + nbytes + cd->tag_len);
	if (len != cd->aad_len + nbytes + cd->tag_len)
		return -1;

	memcpy(out_arg, (char*)cd->data + cd->aad_len, nbytes);
	cd->tag = (char*)cd->data + cd->aad_len + nbytes;

	return nbytes;
}

static int aes_gcm_do_cipher_dec(EVP_CIPHER_CTX *ctx, unsigned char *out_arg, const unsigned char *in_arg, size_t nbytes)
{
	struct cipher_data *cd = CIPHER_DATA(ctx);
	uint32_t op = ALG_OP_DECRYPT;
	struct msghdr msg = {.msg_name = NULL};
	struct cmsghdr *cmsg;
	struct af_alg_iv *ivm;
	struct iovec iov[3];
	char buf[/*op*/CMSG_SPACE(4) + /*af_alg_iv*/CMSG_SPACE(offsetof(struct af_alg_iv, iv) + cd->iv_len) + /*aad_len*/CMSG_SPACE(4)];
	ssize_t len;

	/* EVP_DecryptUpdate(NULL, ...) - set AAD */
	if (out_arg == NULL) {
		/* Must be first EVP_DecryptUpdate() call */
		if (cd->data != NULL)
			return -1;
		/* Must be only EVP_DecryptUpdate(NULL) call */
		if (cd->aad != NULL)
			return -1;
		cd->aad_len = nbytes;
		cd->aad = OPENSSL_malloc(cd->aad_len);
		if (cd->aad == NULL)
			return -1;
		memcpy(cd->aad, in_arg, cd->aad_len);
		return cd->aad_len;
	}

	/* EVP_DecryptFinal_ex() */
	if (in_arg == NULL) {
		/* EVP_DecryptUpdate() not called yet */
		if (cd->data == NULL)
			return -1;
		/* in_arg should match Tag data */
		if (memcmp(out_arg, cd->tag, cd->tag_len) != 0)
			return -1;
		return 0;
	}

	/* Single EVP_DecryptUpdate() only */
	if (cd->data != NULL)
		return -1;

	if (setsockopt(cd->tfmfd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, cd->tag_len) == -1)
		return -1;

	cd->op = accept(cd->tfmfd, NULL, 0);
	if (cd->op == -1)
		return -1;

	cd->data = OPENSSL_malloc(cd->aad_len + nbytes + cd->tag_len);
	if (cd->data == NULL)
		return -1;

	memset(buf, 0, sizeof(buf));

	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	memcpy(CMSG_DATA(cmsg), &op, 4);

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(offsetof(struct af_alg_iv, iv) + cd->iv_len);
	ivm = (void*)CMSG_DATA(cmsg);
	ivm->ivlen = cd->iv_len;
	memcpy(ivm->iv, ctx->iv, cd->iv_len);

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
	cmsg->cmsg_len = CMSG_LEN(4);
	memcpy(CMSG_DATA(cmsg), &cd->aad_len, 4);

	msg.msg_iov = iov;
	msg.msg_iovlen = 0;

	if (cd->aad_len != 0) {
		iov[msg.msg_iovlen].iov_base = cd->aad;
		iov[msg.msg_iovlen].iov_len = cd->aad_len;
		msg.msg_iovlen++;
	}

	iov[msg.msg_iovlen].iov_base = (void*)in_arg;
	iov[msg.msg_iovlen].iov_len = nbytes;
	msg.msg_iovlen++;

	iov[msg.msg_iovlen].iov_base = cd->tag;
	iov[msg.msg_iovlen].iov_len = cd->tag_len;
	msg.msg_iovlen++;

	len = sendmsg(cd->op, &msg, 0);
	if (len != cd->aad_len + nbytes + cd->tag_len)
		return -1;

	len = read(cd->op, cd->data, cd->aad_len + nbytes);
	if (len != cd->aad_len + nbytes)
		return -1;

	memcpy(out_arg, (char*)cd->data + cd->aad_len, nbytes);

	return nbytes;
}

static int aes_gcm_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out_arg, const unsigned char *in_arg, size_t nbytes)
{
	if (ctx->encrypt)
		return aes_gcm_do_cipher_enc(ctx, out_arg, in_arg, nbytes);
	else
		return aes_gcm_do_cipher_dec(ctx, out_arg, in_arg, nbytes);
}

static int aes_gcm_cleanup(EVP_CIPHER_CTX *ctx)
{
	struct cipher_data *cd = CIPHER_DATA(ctx);
	if (cd->tfmfd != -1)
		close(cd->tfmfd);
	if (cd->op != -1)
		close(cd->op);
	if (!ctx->encrypt && cd->tag)
		OPENSSL_free(cd->tag);
	if (cd->aad)
		OPENSSL_free(cd->aad);
	if (cd->data)
		OPENSSL_free(cd->data);
	return 1;
}

#ifndef EVP_CTRL_AEAD_SET_IVLEN
#define EVP_CTRL_AEAD_SET_IVLEN EVP_CTRL_GCM_SET_IVLEN
#define EVP_CTRL_AEAD_SET_TAG EVP_CTRL_GCM_SET_TAG
#define EVP_CTRL_AEAD_GET_TAG EVP_CTRL_GCM_GET_TAG
#endif

static int aes_gcm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
	struct cipher_data *cd = CIPHER_DATA(ctx);

	switch (type) {
		case EVP_CTRL_AEAD_SET_IVLEN:
			if ((arg <= 0) || (arg > EVP_MAX_IV_LENGTH))
				return -1;
			cd->iv_len = arg;
			break;
		case EVP_CTRL_AEAD_GET_TAG:
			if ((arg > cd->tag_len) || (cd->tag == NULL))
				return -1;
			cd->tag_len = arg;
			memcpy(ptr, cd->tag, cd->tag_len);
			break;
		case EVP_CTRL_AEAD_SET_TAG:
			if (ctx->encrypt)
				return -1;
			if (cd->tag != NULL)
				return -1;
			if ((arg <= 0) || (arg > AES_GCM_MAX_TAG_LENGTH))
				return -1;
			cd->tag_len = arg;
			cd->tag = OPENSSL_malloc(cd->tag_len);
			memcpy(cd->tag, ptr, cd->tag_len);
			break;
		default:
			return -1;
	}
	return 1;
}

static EVP_CIPHER *aes_gcm_create(int nid, int key_len)
{
	EVP_CIPHER *cipher = OPENSSL_malloc(sizeof(EVP_CIPHER));
	if (cipher == NULL)
		return NULL;
	memset(cipher, 0, sizeof(EVP_CIPHER));

	cipher->nid = nid;
	cipher->block_size = AES_BLOCK_SIZE;
	cipher->key_len = key_len/8;
	cipher->flags = EVP_CIPH_GCM_MODE|EVP_CIPH_FLAG_CUSTOM_CIPHER|EVP_CIPH_CUSTOM_IV;
	cipher->init = aes_gcm_init;
	cipher->do_cipher = aes_gcm_do_cipher;
	cipher->cleanup = aes_gcm_cleanup;
	cipher->ctx_size = sizeof(struct cipher_data);
	cipher->ctrl = aes_gcm_ctrl;

	return cipher;
}

/**************************************************************************************/

int afalg_set_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
	if (cipher == NULL) {
		*nids = ciphers_used.data;
		return ciphers_used.len;
	}

	if (NID_store_contains(&ciphers_used, nid) == false)
		return 0;

	switch (nid) {
		case NID_aes_128_cbc:
			*cipher = ciphers[0] = aes_cbc_create(NID_aes_128_cbc, 128);
			break;
		case NID_aes_192_cbc:
			*cipher = ciphers[1] = aes_cbc_create(NID_aes_192_cbc, 192);
			break;
		case NID_aes_256_cbc:
			*cipher = ciphers[2] = aes_cbc_create(NID_aes_256_cbc, 256);
			break;
		case NID_aes_128_gcm:
			*cipher = ciphers[3] = aes_gcm_create(NID_aes_128_gcm, 128);
			break;
		case NID_aes_192_gcm:
			*cipher = ciphers[4] = aes_gcm_create(NID_aes_192_gcm, 192);
			break;
		case NID_aes_256_gcm:
			*cipher = ciphers[5] = aes_gcm_create(NID_aes_256_gcm, 256);
			break;
		default:
			*cipher = NULL;
	}

	return (*cipher != NULL);
}

int afalg_unset_ciphers(ENGINE *e)
{
	for (int n = 0; n < 6; n++)
		if (ciphers[n] != NULL)
			OPENSSL_free(ciphers[n]);
	return 1;
}
