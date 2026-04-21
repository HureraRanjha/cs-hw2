#include "handshake.h"
#include "dh.h"
#include "util.h"
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

int doHandshake(int sockfd, dhKey* myLT, dhKey* peerLT,
                unsigned char outKeys[64])
{
	if (!myLT || !peerLT || !outKeys) return -1;

	dhKey myEphem;
	initKey(&myEphem);
	strncpy(myEphem.name, "ephem-mine", MAX_NAME);
	if (dhGenk(&myEphem) != 0) {
		shredKey(&myEphem);
		return -2;
	}

	if (serialize_mpz(sockfd, myEphem.PK) == 0) {
		shredKey(&myEphem);
		return -3;
	}

	dhKey peerEphem;
	initKey(&peerEphem);
	strncpy(peerEphem.name, "ephem-peer", MAX_NAME);
	if (deserialize_mpz(peerEphem.PK, sockfd) != 0) {
		shredKey(&myEphem);
		shredKey(&peerEphem);
		return -4;
	}

	if (dh3Finalk(myLT, &myEphem, peerLT, &peerEphem, outKeys, 64) != 0) {
		shredKey(&myEphem);
		shredKey(&peerEphem);
		return -5;
	}

	shredKey(&myEphem);
	shredKey(&peerEphem);

	unsigned char fp[32];
	SHA256(outKeys, 64, fp);
	fprintf(stderr, "handshake ok -- session key fp: ");
	for (int i = 0; i < 8; i++) fprintf(stderr, "%02x", fp[i]);
	fprintf(stderr, "\n");

	return 0;
}
