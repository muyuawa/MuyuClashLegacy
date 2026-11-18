/* The private packet link drives lwIP callbacks and never opens a system tun. */
#include "utun_device.h"
static utun_device_status_t mlwg_no_device_read(utun_device_t *d,uint8_t *p,size_t n,size_t *used){(void)d;(void)p;(void)n;(void)used;return UTUN_DEVICE_AGAIN;}
static utun_device_status_t mlwg_no_device_write(utun_device_t *d,const uint8_t *p,size_t n){(void)d;(void)p;(void)n;return UTUN_DEVICE_ERR_UNSUPPORTED;}
#define utun_device_read_frame mlwg_no_device_read
#define utun_device_write_frame mlwg_no_device_write
#include "awg_link.c"
