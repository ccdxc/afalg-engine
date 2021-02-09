#ifndef HAVE_E_AF_ALG_H
#define HAVE_E_AF_ALG_H

#include <stdbool.h>
#include <stdint.h>

struct NID_store
{
	size_t len;
	int *data;
};

bool NID_store_contains(struct NID_store *store, int nid);

extern struct NID_store ciphers_available;
extern struct NID_store ciphers_used;

extern struct NID_store digests_available;
extern struct NID_store digests_used;

#endif
