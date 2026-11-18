"""Generate the native TUIC engine from the locked QUIC connection scheduler.

The original dependency is untouched. Only the application authentication,
ALPN/congestion options and application stream callbacks are replaced.
"""
def adapt(source):
    from quic_adapter import adapt as scheduler
    source=scheduler(source)
    def replace(before,after):
        nonlocal source
        if source.count(before)!=1:raise RuntimeError('Pinned TUIC scheduler patch does not match: '+before[:100])
        source=source.replace(before,after)
    replace('    int auth_done;','    int auth_done;\n    void *tuic_context;\n    uint8_t tuic_auth[50], tuic_uuid[16], tuic_alpn[256];\n    size_t tuic_auth_sent, tuic_alpn_length;\n    unsigned tuic_congestion; int tuic_disable_sni;')
    begin=source.index('static int h3_start(hy2_engine_t *e) {');end=source.index('/* ---- quic callbacks',begin)
    source=source[:begin]+'''static int h3_start(hy2_engine_t *e) {
    if (ngtcp2_conn_open_uni_stream(e->conn, &e->auth_stream, NULL) != 0) {
        detail_set(e, "TUIC authentication stream could not open"); return -1;
    }
    e->tuic_auth[0] = 5; e->tuic_auth[1] = 0;
    memcpy(e->tuic_auth + 2, e->tuic_uuid, 16);
    if (SSL_export_keying_material(e->ssl, e->tuic_auth + 18, 32,
          (const char *)e->tuic_uuid, 16, (const uint8_t *)e->auth, strlen(e->auth), 1) != 1) {
        detail_set(e, "TUIC TLS exporter failed"); return -1;
    }
    e->tuic_auth_sent = 0; e->auth_done = 1; ml_tuic_ready(e);
    return 0;
}

'''+source[end:]
    replace('    e->auth_stream = -1;\n    if (udp_open(e, index)', '    e->auth_stream = -1;\n    e->tuic_auth_sent = 0;\n    if (udp_open(e, index)')
    replace('''    static const unsigned char alpn[] = "\\x02h3";
    SSL_set_alpn_protos(e->ssl, alpn, sizeof alpn - 1);''','''    SSL_set_alpn_protos(e->ssl, e->tuic_alpn, e->tuic_alpn_length);''')
    replace('    settings.cc_algo = NGTCP2_CC_ALGO_BBR;','    settings.cc_algo = e->tuic_congestion;')
    replace('        SSL_set_tlsext_host_name(e->ssl, name);','        if (!e->tuic_disable_sni) SSL_set_tlsext_host_name(e->ssl, name);')
    replace('        .handshake_completed = cb_handshake_completed,','        .handshake_completed = cb_handshake_completed,\n        .recv_datagram = ml_tuic_recv_datagram,')
    replace('    ngtcp2_transport_params_default(&params);','    ngtcp2_transport_params_default(&params);\n    params.max_datagram_frame_size = 1200;')
    replace('''    if (stream_is_h3(e, id)) {
        if (!e->h3) return 0;
        nghttp3_ssize used''','''    if (stream_is_h3(e, id)) {
        if (!e->h3) {
            ml_tuic_recv_uni(e, id, data, len, fin);
            (void)ngtcp2_conn_extend_max_stream_offset(e->conn, id, len);
            ngtcp2_conn_extend_max_offset(e->conn, len); return 0;
        }
        nghttp3_ssize used''')
    replace('''    if (stream_is_h3(e, id))
        return e->h3 && nghttp3_conn_add_ack_offset(e->h3, id, len) != 0''','''    if (stream_is_h3(e, id)) {
        if (!e->h3) { ml_tuic_ack(e, id, offset, len); return 0; }
        return e->h3 && nghttp3_conn_add_ack_offset(e->h3, id, len) != 0''')
    replace('''            ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
    hy2_stream_t *s = stream_by_id(e, id);
    if (s && offset''','''            ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
    }
    hy2_stream_t *s = stream_by_id(e, id);
    if (s && offset''')
    replace('''        if (!e->h3) return 0;
        uint32_t h3_flags''','''        if (!e->h3) { ml_tuic_closed_uni(e, id); return 0; }
        uint32_t h3_flags''')
    replace('''static void conn_drop(hy2_engine_t *e, int graceful, int abort_streams) {''','''static void conn_drop(hy2_engine_t *e, int graceful, int abort_streams) {
    ml_tuic_drop(e);''')
    replace('''        if (e->h3 && ngtcp2_conn_get_max_data_left2(e->conn)) {''','''        if (!e->h3 && e->auth_done && e->tuic_auth_sent < sizeof e->tuic_auth) {
            stream_id = e->auth_stream; fin = 1;
            vec[0].base = e->tuic_auth + e->tuic_auth_sent;
            vec[0].len = sizeof e->tuic_auth - e->tuic_auth_sent; vec_count = 1;
        }
        if (e->h3 && ngtcp2_conn_get_max_data_left2(e->conn)) {''')
    replace('''            } else if (e->h3 && nghttp3_conn_add_write_offset''','''            } else if (!e->h3 && stream_id == e->auth_stream) {
                e->tuic_auth_sent += data_len;
            } else if (e->h3 && nghttp3_conn_add_write_offset''')
    replace('''    e->state = HY2_STATE_CONNECTING;
    e->want_connect = 1;''','''    memcpy(e->tuic_uuid, ml_tuic_starting->uuid, 16);
    memcpy(e->tuic_alpn, ml_tuic_starting->alpn, ml_tuic_starting->alpnLength);
    e->tuic_alpn_length = ml_tuic_starting->alpnLength;
    e->tuic_congestion = ml_tuic_starting->congestion;
    e->tuic_disable_sni = ml_tuic_starting->disableSNI;
    e->tuic_context = ml_tuic_start_context;
    e->state = HY2_STATE_CONNECTING;
    e->want_connect = 1;''')
    return source.replace('hysteria2','TUIC')
