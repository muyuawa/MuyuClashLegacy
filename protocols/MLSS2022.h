#ifndef ML_SS2022_H
#define ML_SS2022_H
#include "shadowsocks_client.h"
#include <sys/types.h>
typedef struct MLSS2022 MLSS2022;
int MLSS2022Cipher(const char *method);
int MLSS2022ValidKey(const char *method, const char *password);
MLSS2022 *MLSS2022Open(const char *method, const char *password, const vless_dest_t *dest);
int MLSS2022Request(MLSS2022 *, uint8_t *wire, size_t cap, size_t *length);
int MLSS2022Encrypt(MLSS2022 *, const uint8_t *data, size_t length, uint8_t *wire, size_t cap, size_t *written);
int MLSS2022Feed(MLSS2022 *, const uint8_t *wire, size_t length, uint8_t *data, size_t cap, size_t *written);
int MLSS2022Complete(const MLSS2022 *);
ssize_t MLSS2022UDPEncode(MLSS2022 *, const uint8_t *, size_t, uint8_t *, size_t);
ssize_t MLSS2022UDPDecode(MLSS2022 *, const uint8_t *, size_t, uint8_t *, size_t);
void MLSS2022Close(MLSS2022 *);
#endif
