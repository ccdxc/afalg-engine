#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

#include <openssl/sha.h>
#include <openssl/engine.h>

#include "e_afalg.h"

struct md_data
{
	int tfmfd;
	int opfd;
};

#define MD_DATA(ctx) ((struct md_data*)(ctx->md_data))

EVP_MD *digests[2] = { };

static struct sockaddr_alg sha256_sa = {
	.salg_family = AF_ALG,
	.salg_type = "hash",
	.salg_name = "sha256",
};

static struct sockaddr_alg sha512_sa = {
	.salg_family = AF_ALG,
	.salg_type = "hash",
	.salg_name = "sha512",
};

static int sha256_init(EVP_MD_CTX *ctx)
{
	struct md_data *mdd = MD_DATA(ctx);

	mdd->tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (mdd->tfmfd == -1)
		return 0;

	if (bind(mdd->tfmfd, (struct sockaddr *)&sha256_sa, sizeof(struct sockaddr_alg)) != 0)
		return 0;

	mdd->opfd = accept(mdd->tfmfd, NULL, 0);
	if (mdd->opfd == -1)
		return 0;

	return 1;
}

static int sha512_init(EVP_MD_CTX *ctx)
{
	struct md_data *mdd = MD_DATA(ctx);

	mdd->tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (mdd->tfmfd == -1)
		return 0;

	if (bind(mdd->tfmfd, (struct sockaddr *)&sha512_sa, sizeof(struct sockaddr_alg)) != 0)
		return 0;

	mdd->opfd = accept(mdd->tfmfd, NULL, 0);
	if (mdd->opfd == -1)
		return 0;

	return 1;
}

static int md_update(EVP_MD_CTX *ctx, const void *data, size_t length)
{
	struct md_data *mdd = MD_DATA(ctx);
	ssize_t r;

	r = send(mdd->opfd, data, length, MSG_MORE);
	if ((r < 0) || ((size_t)r < length))
		return 0;

	return 1;
}

static int md_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	struct md_data *mdd = MD_DATA(ctx);
	int md_len = EVP_MD_CTX_size(ctx);

	if (read(mdd->opfd, md, md_len) != md_len)
		return 0;

	return 1;
}

static int md_cleanup(EVP_MD_CTX *ctx)
{
	struct md_data *mdd = MD_DATA(ctx);

	if (mdd->opfd != -1)
		close(mdd->opfd);
	if (mdd->tfmfd != -1)
		close(mdd->tfmfd);

	return 0;
}

static EVP_MD *sha256_create(void)
{
	EVP_MD *digest = OPENSSL_malloc(sizeof(EVP_MD));
	if (digest == NULL)
		return NULL;
	memset(digest, 0, sizeof(EVP_MD));

	digest->type = NID_sha256;
	digest->md_size = SHA256_DIGEST_LENGTH;
	digest->block_size = SHA256_CBLOCK;
	digest->init = sha256_init;
	digest->update = md_update;
	digest->final = md_final;
	digest->cleanup = md_cleanup;
	digest->ctx_size = sizeof(struct md_data);

	return digest;
}

static EVP_MD *sha512_create(void)
{
	EVP_MD *digest = OPENSSL_malloc(sizeof(EVP_MD));
	if (digest == NULL)
		return NULL;
	memset(digest, 0, sizeof(EVP_MD));

	digest->type = NID_sha512;
	digest->md_size = SHA512_DIGEST_LENGTH;
	digest->block_size = SHA512_CBLOCK;
	digest->init = sha512_init;
	digest->update = md_update;
	digest->final = md_final;
	digest->cleanup = md_cleanup;
	digest->ctx_size = sizeof(struct md_data);

	return digest;
}

int afalg_set_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
{
	if (digest == NULL) {
		*nids = digests_used.data;
		return digests_used.len;
	}

	if (NID_store_contains(&digests_used, nid) == false)
		return 0;

	switch (nid) {
		case NID_sha256:
			*digest = digests[0] = sha256_create();
			break;
		case NID_sha512:
			*digest = digests[1] = sha512_create();
			break;
		default:
			*digest = NULL;
			break;
	}

	return (*digest != NULL);
}

int afalg_unset_digests(ENGINE *e)
{
	for (int n = 0; n < 2; n++)
		if (digests[n] != NULL)
			OPENSSL_free(digests[n]);
	return 1;
}
