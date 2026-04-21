/* usage: ./gen-key <file> <name>
 * writes <file> (private) and <file>.pub (public). */
#include <stdio.h>
#include <string.h>
#include "dh.h"
#include "keys.h"

int main(int argc, char* argv[])
{
	if (argc != 3) {
		fprintf(stderr, "usage: %s <file> <name>\n", argv[0]);
		return 1;
	}
	if (init("params") != 0) {
		fprintf(stderr, "could not read DH params from 'params'\n");
		return 1;
	}

	dhKey k;
	initKey(&k);
	strncpy(k.name, argv[2], MAX_NAME);
	k.name[MAX_NAME] = 0;

	if (dhGenk(&k) != 0) { fprintf(stderr, "dhGenk failed\n"); return 1; }
	if (writeDH(argv[1], &k) != 0) {
		fprintf(stderr, "writeDH failed for '%s'\n", argv[1]);
		return 1;
	}

	char fp[65]; fp[64] = 0;
	hashPK(&k, fp);
	printf("wrote %s and %s.pub\n", argv[1], argv[1]);
	printf("name: %s\nfp: %s\n", k.name, fp);

	shredKey(&k);
	return 0;
}
