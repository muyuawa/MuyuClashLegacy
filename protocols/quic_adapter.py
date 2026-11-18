"""Preserve timely Initial emission and bounded fallback in pinned QUIC code."""
def adapt(source):
    changes={
        '    e->attempt_deadline_ms = senko_now_ms() + e->attempt_ms;':'    e->more_to_send = 1; /* emit Initial before polling for its answer */\n    e->attempt_deadline_ms = senko_now_ms() + e->attempt_ms;',
        'e->attempt_ms = config->connect_timeout_ms / (config->address_count > 1 ? 2 : 1);':'e->attempt_ms = config->connect_timeout_ms / config->address_count;\n    if (e->attempt_ms < 1) e->attempt_ms = 1;',
        'e->tries_left = e->config.address_count < 2 ? e->config.address_count : 2;':'e->tries_left = e->config.address_count;',
    }
    for before,after in changes.items():
        if source.count(before)!=1:raise RuntimeError('Pinned QUIC scheduler patch does not match: '+before)
        source=source.replace(before,after)
    return source
