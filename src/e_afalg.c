// ./autogen.sh
// ./configure OPENSSL_CFLAGS="-I /home/c7vpn/openssl/include"

#include <stdio.h>
#include <memory.h>
#include <unistd.h>
#include <sys/socket.h>

#include <openssl/engine.h>

#include "e_afalg.h"

int afalg_set_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid);
int afalg_set_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid);

int afalg_unset_ciphers(ENGINE *e);
int afalg_unset_digests(ENGINE *e);

#define DYNAMIC_ENGINE
#define afalg_ENGINE_ID		"afalg"
#define afalg_ENGINE_NAME	"use AF_ALG for AES CBC/GSM and SHA256/512"

bool NID_store_contains(struct NID_store *store, int nid)
{
	for (size_t i=0; i <store->len; i++) {
		if (store->data[i] == nid)
			return true;
	}
	return false;
}

bool NID_store_add(struct NID_store *store, int nid)
{
	int *r = malloc((store->len + 1)*sizeof(int));
	memcpy(r, store->data, store->len*sizeof(int));
	free(store->data);
	store->data = r;
	store->data[store->len] = nid;
	store->len += 1;
	return true;
}

static int CIPHER_to_nid(const EVP_CIPHER *c)
{
	return EVP_CIPHER_nid(c);
}

static int MD_to_nid(const EVP_MD *d)
{
	return EVP_MD_type(d);
}

static bool NID_store_from_string(struct NID_store *store, struct NID_store *available, const char *names,
								  const void *(*by_name)(const char *),
								  int (*to_nid)(const void *))
{
	char *str, *r;
	char *c = NULL;
	r = str = strdup(names);
	while ((c = strtok_r(r, " ", &r)) != NULL) {
		const void *ec = by_name(c);
		if (ec == NULL) {
			/* the cipher/digest is unknown */
			return false;
		}
		int nid = to_nid(ec);
		if (NID_store_contains(available, nid) == false) {
			/* we do not support the cipher */
			return false;
		}
		if (NID_store_add(store, nid) == false)
			return false;
	}
	return true;
}

int digest_nids[] = {
	NID_sha256,
	NID_sha512,
};

struct NID_store digests_available =
{
	.len = sizeof(digest_nids)/sizeof(digest_nids[0]),
	.data = digest_nids,
};

struct NID_store digests_used =
{
	.len = 0,
};

int cipher_nids[] = {
	NID_aes_128_cbc,
	NID_aes_192_cbc,
	NID_aes_256_cbc,
	NID_aes_128_gcm,
	NID_aes_192_gcm,
	NID_aes_256_gcm,
};

struct NID_store ciphers_available =
{
	.len = sizeof(cipher_nids)/sizeof(cipher_nids[0]),
	.data = cipher_nids,
};

struct NID_store ciphers_used =
{
	.len = 0,
};

int afalg_init(ENGINE *engine)
{
	int sock = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if(sock == -1)
		return 0;
	close(sock);

	return 1;
}

int afalg_finish(ENGINE *engine)
{
	afalg_unset_ciphers(engine);
	afalg_unset_digests(engine);
	return 1;
}

/* The definitions for control commands specific to this engine */
#define afalg_CMD_CIPHERS	(ENGINE_CMD_BASE + 0)
#define afalg_CMD_DIGESTS	(ENGINE_CMD_BASE + 1)

static const ENGINE_CMD_DEFN afalg_cmd_defns[] = {
	{afalg_CMD_CIPHERS, "CIPHERS", "which ciphers to run", ENGINE_CMD_FLAG_STRING},
	{afalg_CMD_DIGESTS, "DIGESTS", "which digests to run", ENGINE_CMD_FLAG_STRING},
	{0, NULL, NULL, 0}
};

static int afalg_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)())
{
	OpenSSL_add_all_algorithms();

	switch (cmd) {
		case afalg_CMD_CIPHERS:
			if (p == NULL)
				return 1;
			if (NID_store_from_string(&ciphers_used, &ciphers_available, p, (void *)EVP_get_cipherbyname, (void *)CIPHER_to_nid) == false)
				return 0;
			ENGINE_unregister_ciphers(e);
			ENGINE_register_ciphers(e);
			return 1;
		case afalg_CMD_DIGESTS:
			if (p == NULL)
				return 1;
			if (NID_store_from_string(&digests_used, &digests_available, p, (void *)EVP_get_digestbyname, (void *)MD_to_nid) == false)
				return 0;
			ENGINE_unregister_digests(e);
			ENGINE_register_digests(e);
			return 1;
		default:
			break;
	}

	return 0;
}

static int afalg_bind_helper(ENGINE *e)
{
	if (!ENGINE_set_id(e, afalg_ENGINE_ID) ||
		!ENGINE_set_init_function(e, afalg_init) ||
		!ENGINE_set_finish_function(e, afalg_finish) ||
		!ENGINE_set_name(e, afalg_ENGINE_NAME) ||
		!ENGINE_set_ciphers (e, afalg_set_ciphers) ||
		!ENGINE_set_digests (e, afalg_set_digests) ||
		!ENGINE_set_ctrl_function(e, afalg_ctrl) ||
		!ENGINE_set_cmd_defns(e, afalg_cmd_defns))
		return 0;
	return 1;
}

ENGINE *ENGINE_afalg(void)
{
	ENGINE *eng = ENGINE_new();
	if (eng == NULL)
		return NULL;

	if (afalg_bind_helper(eng) != 1) {
		ENGINE_free(eng);
		return NULL;
	}

	return eng;
}

static int afalg_bind_fn(ENGINE *e, const char *id)
{
	if ((id != NULL) && (strcmp(id, afalg_ENGINE_ID) != 0))
		return 0;

	if (!afalg_bind_helper(e))
		return 0;

	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(afalg_bind_fn)
