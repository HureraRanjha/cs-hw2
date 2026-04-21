#pragma once
#include <stddef.h>
#include "keys.h"

/* 3DH handshake. outKeys: 32 bytes AES key || 32 bytes HMAC key. */
int doHandshake(int sockfd, dhKey* myLT, dhKey* peerLT,
                unsigned char outKeys[64]);
