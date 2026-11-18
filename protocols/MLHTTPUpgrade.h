#ifndef ML_HTTP_UPGRADE_H
#define ML_HTTP_UPGRADE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define ML_HTTP_UPGRADE_HOST_CAP 256

int MLHTTPUpgradePathValid(const char *path);
/* Validates the HTTP authority and optionally copies the unbracketed host without its port. */
int MLHTTPUpgradeHost(const char *authority, char host[ML_HTTP_UPGRADE_HOST_CAP]);

typedef int (*MLHTTPUpgradeWrite)(void *context, const uint8_t *data, size_t length);
typedef ssize_t (*MLHTTPUpgradeRead)(void *context, uint8_t *data, size_t capacity);

/* Write returns 0 after sending all bytes. On success the caller owns *tail. */
int MLHTTPUpgradeHandshake(const char *path, const char *authority, void *context,
                           MLHTTPUpgradeWrite write, MLHTTPUpgradeRead read,
                           uint8_t **tail, size_t *tailLength);

#endif
