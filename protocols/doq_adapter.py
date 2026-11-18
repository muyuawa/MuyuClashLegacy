"""Isolate RFC 9250 DNS-over-QUIC on the pinned native QUIC scheduler."""
def adapt(source):
    from quic_adapter import adapt as scheduler
    source=scheduler(source)
    begin=source.index('static int h3_start(hy2_engine_t *e) {')
    end=source.index('/* ---- quic callbacks',begin)
    source=source[:begin]+'''static int h3_start(hy2_engine_t *e) {
    const unsigned char *protocol = NULL; unsigned int length = 0;
    SSL_get0_alpn_selected(e->ssl, &protocol, &length);
    if (length != 3 || memcmp(protocol, "doq", 3)) {
        detail_set(e, "the DNS server did not negotiate ALPN doq"); return -1;
    }
    e->auth_done = 1;
    return 0;
}

'''+source[end:]
    old='static const unsigned char alpn[] = "\\x02h3";'
    if source.count(old)!=1:raise RuntimeError('Pinned DoQ ALPN patch does not match')
    source=source.replace(old,'static const unsigned char alpn[] = "\\x03" "doq";')
    return source.replace('hysteria2','DNS-over-QUIC')
