#import <Foundation/Foundation.h>
#import "MLStream.h"

#include "http_client.h"
#include "shadowsocks_client.h"
#include "socks5_client.h"
#include "trojan_client.h"
#include "vless_conn.h"
#include "vmess_client.h"
#include "hy2_engine.h"
#include "MLHy2Engine.h"
#include "MLTUICEngine.h"
#include "MLWireGuard.h"
#include <ngtcp2/ngtcp2.h>
#include "reality_handshake.h"
#include "b64.h"
#include "vision.h"
#include "vless_udp.h"
#include "MLShadowsocksUDP.h"
#include "MLSS2022.h"
#include "MLSSR.h"
#include "MLSnell.h"
#include "MLSSH.h"
#include "MLAnyTLS.h"
#include "MLHTTPUpgrade.h"
#include "MLXHTTPTransport.h"
#include "core/hy2_proto.h"
#include "../transport/MLNetworkBinding.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach_time.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef MLSTREAM_CA_BUNDLE
#define MLSTREAM_CA_BUNDLE "/usr/share/muyuclash/cacert.pem"
#endif

#define ML_PLAIN_CAP 16384
#define ML_TX_CAP 8192
#define ML_WS_HEADER_CAP 8
#define ML_OUTPUT_CAP (ML_TX_CAP + ML_WS_HEADER_CAP)

typedef enum {
    MLDirect, MLHTTP, MLSOCKS5, MLVLESS, MLVMess, MLTrojan, MLShadowsocks, MLHysteria2, MLReject, MLSSHProtocol, MLAnyTLSProtocol, MLTUICProtocol, MLWireGuardProtocol, MLSnellProtocol, MLShadowsocksR
} MLProtocol;

typedef struct {
    MLProtocol protocol;
    int tls, websocket, httpUpgrade, reality, vision, packet, http2, udpEnabled;
    uint16_t port;
    char server[256], sni[256], user[64], pass[256], cipher[32];
    char wsPath[256], wsHost[256];
    char obfs[129], pin[65];
    char publicKey[45], shortID[17], fingerprint[24];
    char http2Path[256], http2Mode[16], http2Host[256];
    char dialer[256];
    char sshPrivateKey[8192], sshPassphrase[256], sshHostKeys[4096], sshAlgorithms[256];
    char ssrProtocol[24], ssrObfs[16], ssrProtocolParam[256], ssrObfsParam[1025], snellMode[16];
    unsigned snellVersion;
    unsigned idleCheck, idleTimeout, minIdle;
    unsigned quicCongestion, quicHeartbeat, quicMaxPayload;
    int quicReliableUDP, quicDisableSNI;
    uint8_t quicALPN[256]; size_t quicALPNLength;
    const char *rawJSON;
    uint8_t uuid[VLESS_UUID_LEN];
} MLNode;

typedef struct {
    uint8_t *initial;
    size_t initialOffset, initialLength;
    uint64_t remaining;
    uint8_t header[10], incomingControl[125], reply[131];
    size_t headerLength, headerNeeded, controlLength, replyOffset, replyLength;
    uint8_t opcode;
    int fragmented, closeQueued, peerClosed;
} MLWebSocket;

typedef struct MLHy2Shared MLHy2Shared;
typedef struct {
    vision_traffic_t traffic;
    vision_wrap_t up;
    vision_unpad_t down;
    int first, pendingDirect, upstreamDirect, downstreamDirect;
} MLVision;

struct MLStream {
    int fd;
    MLStream *lower;
    MLProtocol protocol;
    MLHy2Shared *hy2;
    void *hy2Handle;
    void *realityHandle;
    void *http2Handle;
    vless_dest_t socksRelay;
    MLVision *vision;
    SSL *tls;
    MLWebSocket *websocket;
    void *codec;
    MLSS2022 *ss2022;
    MLSSR *ssr;
    MLSnell *snell;
    MLSSH *ssh;
    MLAnyTLS *anytls;
    MLWGSession *wireguard;
    size_t codecSize;
    uint8_t *in, *out;
    size_t inOffset, inLength, outOffset, outLength;
    uint8_t *upgradeTail;
    size_t upgradeOffset, upgradeLength;
    short readEvents, writeEvents;
    int readEnded, writeClosing, writeEnded, stagedRead;
    int shutdownFrameQueued, http2Closing;
    int permanentError;
};

static BOOL copyText(id value, char *result, size_t size) {
    if (![value isKindOfClass:[NSString class]]) return NO;
    NSData *bytes = [value dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
    if (!bytes.length || bytes.length >= size || memchr(bytes.bytes, 0, bytes.length)) return NO;
    memcpy(result, bytes.bytes, bytes.length);
    result[bytes.length] = '\0';
    return YES;
}

static BOOL booleanValue(id object) {
    return [object isKindOfClass:[NSNumber class]] &&
        CFGetTypeID((__bridge CFTypeRef)object) == CFBooleanGetTypeID();
}

static BOOL integerValue(id object, long minimum, long maximum) {
    if (![object isKindOfClass:[NSNumber class]] || booleanValue(object)) return NO;
    double value = [object doubleValue];
    return value >= minimum && value <= maximum && value == [object longLongValue];
}

static unsigned nodePort(id object) {
    if (integerValue(object, 1, 65535)) return [object unsignedShortValue];
    char digits[6];
    if (!copyText(object, digits, sizeof digits)) return 0;
    for (const char *digit = digits; *digit; digit++) if (*digit < '0' || *digit > '9') return 0;
    unsigned long value = strtoul(digits, NULL, 10);
    return value <= 65535 ? (unsigned)value : 0;
}

static BOOL hostAddress(const char *host, uint16_t port, vless_dest_t *dest) {
    size_t length = strnlen(host, sizeof dest->domain);
    if (!length || length >= sizeof dest->domain || !port) return NO;
    memset(dest, 0, sizeof *dest);
    dest->port = port;
    if (inet_pton(AF_INET, host, dest->host_addr) == 1) {
        dest->atyp = VLESS_ADDR_IPV4;
        return YES;
    }
    if (inet_pton(AF_INET6, host, dest->host_addr) == 1) {
        dest->atyp = VLESS_ADDR_IPV6;
        return YES;
    }
    if (host[0] == '.' || host[0] == '-') return NO;
    for (const unsigned char *p = (const unsigned char *)host; *p; p++) {
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9') || *p == '.' || *p == '-' || *p == '_') continue;
        return NO;
    }
    memcpy(dest->domain, host, length + 1);
    dest->atyp = VLESS_ADDR_DOMAIN;
    return YES;
}

static BOOL httpTokenText(const char *text) {
    for (const unsigned char *byte = (const unsigned char *)text; *byte; byte++) {
        if (*byte <= 32 || *byte >= 127 || *byte == '#') return NO;
    }
    return YES;
}

static int readSocksAddress(const uint8_t *data, size_t size, vless_dest_t *out, size_t *used) {
    if (!size) return 0;
    memset(out, 0, sizeof *out); size_t length = 0, offset = 1;
    if (data[0] == 1) { out->atyp = VLESS_ADDR_IPV4; length = 4; }
    else if (data[0] == 4) { out->atyp = VLESS_ADDR_IPV6; length = 16; }
    else if (data[0] == 3) {
        if (size < 2) return 0;
        out->atyp = VLESS_ADDR_DOMAIN; length = data[1]; offset = 2;
        if (!length) { errno = EPROTO; return -1; }
    } else { errno = EPROTO; return -1; }
    if (size < offset + length + 2) return 0;
    if (out->atyp == VLESS_ADDR_DOMAIN) {
        memcpy(out->domain, data + offset, length); vless_dest_t check;
        if (!hostAddress(out->domain, 1, &check)) { errno = EPROTO; return -1; }
    } else memcpy(out->host_addr, data + offset, length);
    out->port = ((uint16_t)data[offset + length] << 8) | data[offset + length + 1];
    if (!out->port) { errno = EPROTO; return -1; }
    *used = offset + length + 2; return 1;
}

static NSString *parseWebSocketOptions(id value, MLNode *out) {
    if (![value isKindOfClass:[NSDictionary class]]) return @"ws-opts";
    NSDictionary *options = value;
    for (NSString *key in options) {
        if (![@[@"path", @"headers", @"max-early-data", @"v2ray-http-upgrade", @"v2ray-http-upgrade-fast-open"] containsObject:key]) return @"ws-opts";
    }
    id upgrade = options[@"v2ray-http-upgrade"], fastOpen = options[@"v2ray-http-upgrade-fast-open"];
    if (upgrade && !booleanValue(upgrade)) return @"ws-opts.v2ray-http-upgrade";
    if (fastOpen && (!booleanValue(fastOpen) || [fastOpen boolValue])) return @"ws-opts.v2ray-http-upgrade-fast-open";
    out->httpUpgrade = [upgrade boolValue];
    id path = options[@"path"];
    if (path && (!copyText(path, out->wsPath, sizeof out->wsPath) ||
                 out->wsPath[0] != '/' || !httpTokenText(out->wsPath))) return @"ws-opts";
    if (options[@"max-early-data"] && !integerValue(options[@"max-early-data"], 0, 0)) return @"ws-opts";
    id headers = options[@"headers"];
    if (!headers) return nil;
    if (![headers isKindOfClass:[NSDictionary class]] || [headers count] > 1) return @"ws-opts";
    for (NSString *key in headers) {
        if ([key caseInsensitiveCompare:@"Host"] != NSOrderedSame ||
            !copyText(headers[key], out->wsHost, sizeof out->wsHost) || !httpTokenText(out->wsHost)) return @"ws-opts";
        if (out->httpUpgrade && !MLHTTPUpgradeHost(out->wsHost, NULL)) return @"ws-opts.headers.Host";
    }
    return nil;
}

static NSString *parseNode(NSDictionary *node, MLNode *out) {
    if (![node isKindOfClass:[NSDictionary class]]) return @"type";
    NSString *type = [node[@"type"] isKindOfClass:[NSString class]] ? [node[@"type"] lowercaseString] : nil;
    if ([type isEqual:@"direct"] || [type isEqual:@"reject"]) {
        out->protocol = [type isEqual:@"reject"] ? MLReject : MLDirect;
        for (NSString *key in node) if (![@[@"name", @"type", @"udp"] containsObject:key]) return key;
        if (node[@"udp"] && !booleanValue(node[@"udp"])) return @"udp";
        return nil;
    }
    if ([@[@"wireguard", @"amneziawg", @"amnezia-wg", @"awg"] containsObject:type]) {
        out->protocol = MLWireGuardProtocol; return MLWGValidateNode(node);
    }
    NSArray *options;
    if ([type isEqual:@"http"] || [type isEqual:@"https"]) {
        out->protocol = MLHTTP;
        out->tls = [type isEqual:@"https"];
        options = @[@"username", @"password", @"tls", @"sni", @"servername"];
    } else if ([type isEqual:@"socks5"]) {
        out->protocol = MLSOCKS5;
        options = @[@"username", @"password", @"tls", @"sni", @"servername"];
    } else if ([type isEqual:@"vless"]) {
        out->protocol = MLVLESS;
        options = @[@"uuid", @"tls", @"sni", @"servername", @"network", @"encryption", @"ws-opts", @"reality-opts", @"client-fingerprint", @"flow", @"grpc-opts", @"xhttp-opts"];
    } else if ([type isEqual:@"vmess"]) {
        out->protocol = MLVMess;
        options = @[@"uuid", @"cipher", @"alterId", @"tls", @"sni", @"servername", @"network", @"ws-opts", @"grpc-opts", @"xhttp-opts"];
    } else if ([type isEqual:@"trojan"]) {
        out->protocol = MLTrojan;
        out->tls = 1;
        options = @[@"password", @"tls", @"sni", @"servername", @"network", @"ws-opts", @"grpc-opts", @"xhttp-opts"];
    } else if ([type isEqual:@"hysteria2"] || [type isEqual:@"hy2"]) {
        out->protocol = MLHysteria2;
        options = @[@"password", @"sni", @"servername", @"obfs", @"obfs-password", @"fingerprint", @"alpn", @"client-fingerprint"];
    } else if ([type isEqual:@"ss"]) {
        out->protocol = MLShadowsocks;
        options = @[@"cipher", @"password"];
    } else if ([type isEqual:@"ssr"]) {
        out->protocol = MLShadowsocksR;
        options = @[@"cipher", @"password", @"protocol", @"protocol-param", @"obfs", @"obfs-param"];
    } else if ([type isEqual:@"snell"]) {
        out->protocol = MLSnellProtocol;
        options = @[@"psk", @"version", @"mode", @"reuse"];
    } else if ([type isEqual:@"ssh"]) {
        out->protocol = MLSSHProtocol;
        options = @[@"username", @"password", @"private-key", @"private-key-passphrase", @"host-key", @"host-key-algorithms"];
    } else if ([type isEqual:@"anytls"]) {
        out->protocol = MLAnyTLSProtocol; out->tls = 1;
        options = @[@"password", @"tls", @"sni", @"servername", @"idle-session-check-interval", @"idle-session-timeout", @"min-idle-session"];
    } else if ([type isEqual:@"tuic"]) {
        out->protocol = MLTUICProtocol;
        options = @[@"uuid", @"password", @"sni", @"servername", @"fingerprint", @"alpn", @"congestion-controller", @"udp-relay-mode", @"heartbeat-interval", @"disable-sni", @"max-udp-relay-packet-size", @"reduce-rtt"];
    } else {
        return @"type";
    }

    NSArray *common = @[@"name", @"type", @"server", @"port", @"udp", @"skip-cert-verify", @"dialer-proxy"];
    for (NSString *key in [[node allKeys] sortedArrayUsingSelector:@selector(compare:)]) {
        if (![common containsObject:key] && ![options containsObject:key]) return key;
    }
    vless_dest_t address;
    if (!copyText(node[@"server"], out->server, sizeof out->server) || !hostAddress(out->server, 1, &address))
        return @"server";
    out->port = (uint16_t)nodePort(node[@"port"]);
    if (!out->port) return @"port";
    if (node[@"dialer-proxy"] && !copyText(node[@"dialer-proxy"], out->dialer, sizeof out->dialer)) return @"dialer-proxy";
    for (NSString *key in @[@"udp", @"skip-cert-verify"]) {
        if (node[key] && (!booleanValue(node[key]) || ([node[key] boolValue] && !([key isEqual:@"udp"] &&
            (out->protocol == MLHysteria2 || out->protocol == MLTUICProtocol || out->protocol == MLVLESS || out->protocol == MLVMess || out->protocol == MLTrojan || out->protocol == MLShadowsocks || out->protocol == MLSOCKS5 || out->protocol == MLAnyTLSProtocol || out->protocol == MLSnellProtocol || out->protocol == MLShadowsocksR))))) return key;
    }
    out->udpEnabled = [node[@"udp"] boolValue];
    if (node[@"network"]) {
        out->websocket = [node[@"network"] isEqual:@"ws"];
        out->http2 = [node[@"network"] isEqual:@"grpc"] ? 1 : [node[@"network"] isEqual:@"xhttp"] ? 2 : 0;
        if (!out->websocket && !out->http2 && ![node[@"network"] isEqual:@"tcp"]) return @"network";
    }
    if (node[@"ws-opts"]) {
        if (!out->websocket) return @"ws-opts";
        NSString *unsupported = parseWebSocketOptions(node[@"ws-opts"], out);
        if (unsupported) return unsupported;
    }
    if (node[@"grpc-opts"] && out->http2 != 1) return @"grpc-opts";
    if (node[@"xhttp-opts"] && out->http2 != 2) return @"xhttp-opts";
    if (out->http2 == 1) {
        id options = node[@"grpc-opts"];
        if (![options isKindOfClass:[NSDictionary class]]) return @"grpc-opts";
        for (NSString *key in options) if (![@[@"grpc-service-name"] containsObject:key]) return @"grpc-opts";
        char service[240];
        if (!copyText(options[@"grpc-service-name"], service, sizeof service) || strspn(service, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != strlen(service)) return @"grpc-opts.grpc-service-name";
        snprintf(out->http2Path, sizeof out->http2Path, "/%s/Tun", service); strcpy(out->http2Mode, "grpc");
    } else if (out->http2 == 2) {
        id options = node[@"xhttp-opts"];
        if (![options isKindOfClass:[NSDictionary class]]) return @"xhttp-opts";
        for (NSString *key in options) if (![@[@"path", @"mode", @"host"] containsObject:key]) return @"xhttp-opts";
        if (!copyText(options[@"path"] ?: @"/", out->http2Path, sizeof out->http2Path) || out->http2Path[0] != '/' || !httpTokenText(out->http2Path)) return @"xhttp-opts.path";
        id mode = options[@"mode"] ?: @"auto";
        if (![@[@"auto", @"stream-one", @"stream-up", @"packet-up"] containsObject:mode] || !copyText(mode, out->http2Mode, sizeof out->http2Mode)) return @"xhttp-opts.mode";
        if (options[@"host"] && (!copyText(options[@"host"], out->http2Host, sizeof out->http2Host) || !httpTokenText(out->http2Host))) return @"xhttp-opts.host";
    }
    if (node[@"tls"]) {
        if (!booleanValue(node[@"tls"]) || (out->tls && ![node[@"tls"] boolValue])) return @"tls";
        out->tls = [node[@"tls"] boolValue];
    }
    if (node[@"reality-opts"]) {
        if (out->protocol != MLVLESS || !out->tls || ![node[@"reality-opts"] isKindOfClass:[NSDictionary class]]) return @"reality-opts";
        NSDictionary *reality = node[@"reality-opts"];
        for (NSString *key in reality) if (![@[@"public-key", @"short-id"] containsObject:key]) return @"reality-opts";
        uint8_t decoded[32]; size_t length = 0;
        if (!copyText(reality[@"public-key"], out->publicKey, sizeof out->publicKey) ||
            b64_decode(out->publicKey, strlen(out->publicKey), decoded, sizeof decoded, &length) || length != 32) return @"reality-opts.public-key";
        id sid = reality[@"short-id"];
        if (sid && (![sid isKindOfClass:[NSString class]] || [sid length] > 16 || [sid length] % 2 ||
                    ([sid length] && (!copyText(sid, out->shortID, sizeof out->shortID) || strspn(out->shortID, "0123456789abcdefABCDEF") != strlen(out->shortID))))) return @"reality-opts.short-id";
        out->reality = 1;
        if (out->websocket) return @"network";
    }
    if (node[@"client-fingerprint"]) {
        if (out->protocol == MLHysteria2) {
            // Fixed Mihomo baseline has no Hysteria2 client-fingerprint field;
            // retain compatible metadata and report its lack of wire effect.
            if (!copyText(node[@"client-fingerprint"], out->fingerprint, sizeof out->fingerprint)) return @"client-fingerprint";
        } else if (!out->reality || ![@[@"chrome", @"chrome_auto", @"firefox", @"edge", @"qq", @"random", @"randomized"] containsObject:node[@"client-fingerprint"]] ||
                   !copyText(node[@"client-fingerprint"], out->fingerprint, sizeof out->fingerprint)) return @"client-fingerprint";
    }
    if (node[@"flow"]) {
        if (out->protocol != MLVLESS || !out->tls || out->websocket || out->http2 || ![node[@"flow"] isEqual:@"xtls-rprx-vision"]) return @"flow";
        out->vision = 1;
    }
    for (NSString *key in @[@"sni", @"servername"]) {
        if (!node[key]) continue;
        char value[256];
        if ((!out->tls && out->protocol != MLHysteria2 && out->protocol != MLTUICProtocol) || !copyText(node[key], value, sizeof value) || !hostAddress(value, 1, &address) ||
            (out->sni[0] && strcmp(out->sni, value) != 0)) return key;
        strcpy(out->sni, value);
    }
    if (out->httpUpgrade && out->tls && out->protocol != MLTrojan && !out->sni[0] && out->wsHost[0])
        MLHTTPUpgradeHost(out->wsHost, out->sni);
    if (out->reality && !out->sni[0]) return @"servername";
    if (out->protocol == MLHTTP || out->protocol == MLSOCKS5) {
        BOOL user = node[@"username"] != nil;
        BOOL pass = node[@"password"] != nil;
        if (user && (!copyText(node[@"username"], out->user, sizeof out->user) ||
                     (out->protocol == MLHTTP && strchr(out->user, ':')))) return @"username";
        if (pass && !copyText(node[@"password"], out->pass, sizeof ((http_client_t *)0)->pass)) return @"password";
        if (user != pass) return user ? @"password" : @"username";
    }
    if (out->protocol == MLVLESS || out->protocol == MLVMess || out->protocol == MLTUICProtocol) {
        char uuid[37];
        if (!copyText(node[@"uuid"], uuid, sizeof uuid) || strlen(uuid) != 36 ||
            uuid[8] != '-' || uuid[13] != '-' || uuid[18] != '-' || uuid[23] != '-' ||
            vless_uuid_parse(uuid, out->uuid) != VLESS_OK) return @"uuid";
    }
    if (out->protocol == MLVLESS && node[@"encryption"] && ![node[@"encryption"] isEqual:@"none"])
        return @"encryption";
    if (out->protocol == MLVMess) {
        if (node[@"alterId"] && !integerValue(node[@"alterId"], 0, 0)) return @"alterId";
        id cipher = node[@"cipher"] ?: @"auto";
        if (![@[@"auto", @"aes-128-gcm", @"chacha20-poly1305"] containsObject:cipher] ||
            !copyText(cipher, out->cipher, sizeof out->cipher)) return @"cipher";
    }
    if (out->protocol == MLHysteria2 || out->protocol == MLTUICProtocol) {
        if (!copyText(node[@"password"], out->pass, sizeof out->pass)) return @"password";
        if (node[@"obfs"] && ![node[@"obfs"] isEqual:@"salamander"]) return @"obfs";
        if (node[@"obfs-password"] && (!node[@"obfs"] || !copyText(node[@"obfs-password"], out->obfs, sizeof out->obfs))) return @"obfs-password";
        if (node[@"obfs"] && !out->obfs[0]) return @"obfs-password";
        if (node[@"fingerprint"]) {
            if (![node[@"fingerprint"] isKindOfClass:[NSString class]]) return @"fingerprint";
            NSString *pin = [[node[@"fingerprint"] stringByReplacingOccurrencesOfString:@":" withString:@""] lowercaseString];
            if (!copyText(pin, out->pin, sizeof out->pin) || strlen(out->pin) != 64 || strspn(out->pin, "0123456789abcdef") != 64) return @"fingerprint";
        }
    }
    if (out->protocol == MLHysteria2 && node[@"alpn"]) {
        // The Hy2 engine negotiates RFC 9114 h3. Accept the explicit standard
        // spelling, while rejecting an ALPN the transport cannot negotiate.
        id alpn = node[@"alpn"];
        if (![alpn isKindOfClass:[NSArray class]] || [alpn count] != 1 || ![alpn[0] isEqual:@"h3"]) return @"alpn";
    }
    if (out->protocol == MLTUICProtocol) {
        NSArray *alpn = node[@"alpn"] ?: @[@"h3"];
        if (![alpn isKindOfClass:[NSArray class]] || !alpn.count) return @"alpn";
        for (id value in alpn) {
            char name[256]; if (!copyText(value, name, sizeof name)) return @"alpn";
            size_t length = strlen(name); if (out->quicALPNLength + 1 + length > sizeof out->quicALPN) return @"alpn";
            out->quicALPN[out->quicALPNLength++] = (uint8_t)length;
            memcpy(out->quicALPN + out->quicALPNLength, name, length); out->quicALPNLength += length;
        }
        id cc = node[@"congestion-controller"] ?: @"cubic";
        if (![@[@"cubic", @"new_reno", @"bbr"] containsObject:cc]) return @"congestion-controller";
        out->quicCongestion = [cc isEqual:@"bbr"] ? NGTCP2_CC_ALGO_BBR : [cc isEqual:@"cubic"] ? NGTCP2_CC_ALGO_CUBIC : NGTCP2_CC_ALGO_RENO;
        id relay = node[@"udp-relay-mode"] ?: @"native";
        if (![@[@"native", @"quic"] containsObject:relay]) return @"udp-relay-mode";
        out->quicReliableUDP = [relay isEqual:@"quic"];
        if (node[@"heartbeat-interval"] && !integerValue(node[@"heartbeat-interval"], 1, 86400000)) return @"heartbeat-interval";
        if (node[@"max-udp-relay-packet-size"] && !integerValue(node[@"max-udp-relay-packet-size"], 1, 1500)) return @"max-udp-relay-packet-size";
        out->quicHeartbeat = [node[@"heartbeat-interval"] unsignedIntValue]; out->quicMaxPayload = [node[@"max-udp-relay-packet-size"] unsignedIntValue];
        if (node[@"disable-sni"] && !booleanValue(node[@"disable-sni"])) return @"disable-sni";
        out->quicDisableSNI = [node[@"disable-sni"] boolValue];
        if (node[@"reduce-rtt"] && (!booleanValue(node[@"reduce-rtt"]) || [node[@"reduce-rtt"] boolValue])) return @"reduce-rtt";
    }
    if ((out->protocol == MLTrojan || out->protocol == MLShadowsocks) &&
        !copyText(node[@"password"], out->pass, sizeof out->pass)) return @"password";
    if (out->protocol == MLShadowsocks &&
        (!copyText(node[@"cipher"], out->cipher, sizeof out->cipher) ||
         (ss_cipher_from_name(out->cipher) == SS_CIPHER_UNKNOWN && !MLSS2022Cipher(out->cipher)))) return @"cipher";
    if (out->protocol == MLShadowsocks && MLSS2022Cipher(out->cipher) && !MLSS2022ValidKey(out->cipher, out->pass)) return @"password";
    if (out->protocol == MLShadowsocksR) {
        if (!copyText(node[@"cipher"], out->cipher, sizeof out->cipher) || !MLSSRCipher(out->cipher)) return @"cipher";
        if (!copyText(node[@"password"], out->pass, sizeof out->pass)) return @"password";
        if (!copyText(node[@"protocol"], out->ssrProtocol, sizeof out->ssrProtocol) || !MLSSRProtocol(out->ssrProtocol)) return @"protocol";
        if (!copyText(node[@"obfs"], out->ssrObfs, sizeof out->ssrObfs) || !MLSSRObfs(out->ssrObfs)) return @"obfs";
        if (node[@"protocol-param"] && ![node[@"protocol-param"] isEqual:@""] &&
            !copyText(node[@"protocol-param"], out->ssrProtocolParam, sizeof out->ssrProtocolParam)) return @"protocol-param";
        if (node[@"obfs-param"] && ![node[@"obfs-param"] isEqual:@""] &&
            !copyText(node[@"obfs-param"], out->ssrObfsParam, sizeof out->ssrObfsParam)) return @"obfs-param";
        if (!MLSSRParameters(out->ssrProtocol, out->ssrProtocolParam, "plain", "")) return @"protocol-param";
        if (!MLSSRParameters("origin", "", out->ssrObfs, out->ssrObfsParam)) return @"obfs-param";
    }
    if (out->protocol == MLSnellProtocol) {
        if (node[@"version"] && !integerValue(node[@"version"], 0, 6)) return @"version";
        out->snellVersion = [node[@"version"] unsignedIntValue];
        if (!copyText(node[@"psk"], out->pass, sizeof out->pass) ||
            !MLSnellOptions(out->snellVersion, NULL, out->pass, 0)) return @"psk";
        if (node[@"mode"] && ![node[@"mode"] isEqual:@""] &&
            (!copyText(node[@"mode"], out->snellMode, sizeof out->snellMode) ||
             !MLSnellOptions(out->snellVersion, out->snellMode, out->pass, 0))) return @"mode";
        if ([node[@"udp"] boolValue] && !MLSnellOptions(out->snellVersion, out->snellMode, out->pass, 1)) return @"udp";
        if (node[@"reuse"] && (!booleanValue(node[@"reuse"]) || [node[@"reuse"] boolValue])) return @"reuse";
    }
    if (out->protocol == MLSSHProtocol) {
        if (!copyText(node[@"username"], out->user, sizeof out->user)) return @"username";
        if (node[@"private-key"]) {
            if (!copyText(node[@"private-key"], out->sshPrivateKey, sizeof out->sshPrivateKey) || !strstr(out->sshPrivateKey, "PRIVATE KEY-----")) return @"private-key";
            if (node[@"private-key-passphrase"] && !copyText(node[@"private-key-passphrase"], out->sshPassphrase, sizeof out->sshPassphrase)) return @"private-key-passphrase";
        } else if (!copyText(node[@"password"], out->pass, sizeof out->pass)) return @"password";
        NSArray *pins = node[@"host-key"];
        if (![pins isKindOfClass:[NSArray class]] || pins.count == 0 || pins.count > 16) return @"host-key";
        for (id pin in pins) if (![pin isKindOfClass:[NSString class]] || ![pin length] || [pin rangeOfCharacterFromSet:[NSCharacterSet newlineCharacterSet]].location != NSNotFound) return @"host-key";
        if (!copyText([pins componentsJoinedByString:@"\n"], out->sshHostKeys, sizeof out->sshHostKeys)) return @"host-key";
        if (node[@"host-key-algorithms"]) {
            NSArray *algorithms = node[@"host-key-algorithms"];
            if (![algorithms isKindOfClass:[NSArray class]] || !algorithms.count) return @"host-key-algorithms";
            for (id value in algorithms) if (![@[@"ssh-ed25519", @"ecdsa-sha2-nistp256", @"ecdsa-sha2-nistp384", @"ecdsa-sha2-nistp521", @"rsa-sha2-256", @"rsa-sha2-512"] containsObject:value]) return @"host-key-algorithms";
            if (!copyText([algorithms componentsJoinedByString:@","], out->sshAlgorithms, sizeof out->sshAlgorithms)) return @"host-key-algorithms";
        }
    }
    if (out->protocol == MLAnyTLSProtocol) {
        if (!copyText(node[@"password"], out->pass, sizeof out->pass)) return @"password";
        for (NSString *key in @[@"idle-session-check-interval", @"idle-session-timeout", @"min-idle-session"]) {
            if (node[key] && !integerValue(node[key], [key isEqual:@"min-idle-session"] ? 0 : 1, [key isEqual:@"min-idle-session"] ? 8 : 86400)) return key;
        }
        out->idleCheck = [node[@"idle-session-check-interval"] unsignedIntValue];
        out->idleTimeout = [node[@"idle-session-timeout"] unsignedIntValue];
        out->minIdle = [node[@"min-idle-session"] unsignedIntValue];
    }
    return nil;
}

NSString *MLStreamValidateNode(NSDictionary *node) {
    MLNode parsed = {0};
    NSString *error = parseNode(node, &parsed);
    OPENSSL_cleanse(&parsed, sizeof parsed);
    return error;
}

static int parseJSON(const char *json, MLNode *out) {
    if (!json) return 0;
    @autoreleasepool {
        size_t length = strnlen(json, 65536);
        if (length == 0 || length == 65536) { errno = EINVAL; return -1; }
        NSData *data = [NSData dataWithBytesNoCopy:(void *)json length:length freeWhenDone:NO];
        id node = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
        if (![node isKindOfClass:[NSDictionary class]]) { errno = EINVAL; return -1; }
        if (parseNode(node, out)) { errno = ENOTSUP; return -1; }
        if (out->protocol == MLWireGuardProtocol) out->rawJSON = json;
    }
    return 0;
}

int MLStreamValidate(const char *nodeJSON) {
    MLNode parsed = {0};
    int result = parseJSON(nodeJSON, &parsed);
    OPENSSL_cleanse(&parsed, sizeof parsed);
    return result;
}

static mach_timebase_info_data_t machTimebase;
static void loadMachTimebase(void) { mach_timebase_info(&machTimebase); }

static uint64_t nowMS(void) {
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, loadMachTimebase);
    return (uint64_t)((long double)mach_absolute_time() * machTimebase.numer / machTimebase.denom / 1000000.0L);
}

/* A bounded pool shares one authenticated QUIC connection between concurrent
   streams for the same immutable node. Last close joins the engine thread. */
struct MLHy2Shared {
    MLNode node;
    hy2_engine_t *engine;
    unsigned refs, timeout, interfaceIndex;
};
static pthread_mutex_t hy2PoolLock = PTHREAD_MUTEX_INITIALIZER;
static MLHy2Shared *hy2Pool[8];

static MLHy2Shared *acquireHy2(const MLNode *node, uint64_t deadline) {
    uint64_t now = nowMS();
    if (deadline <= now + 1000) { errno = ETIMEDOUT; return NULL; }
    unsigned timeout = (unsigned)MIN(deadline - now - 1000, 10000);
    pthread_mutex_lock(&hy2PoolLock);
    for (size_t i = 0; i < sizeof hy2Pool / sizeof hy2Pool[0]; ++i) {
        MLHy2Shared *entry = hy2Pool[i];
        if (entry && entry->interfaceIndex == MLNetworkInterfaceIndex() && !memcmp(&entry->node, node, sizeof *node) && entry->timeout <= timeout && entry->timeout + 1000 >= timeout) {
            ++entry->refs;
            pthread_mutex_unlock(&hy2PoolLock);
            return entry;
        }
    }
    size_t freeSlot = sizeof hy2Pool / sizeof hy2Pool[0];
    for (size_t i = 0; i < freeSlot; ++i) if (!hy2Pool[i]) { freeSlot = i; break; }
    if (freeSlot == sizeof hy2Pool / sizeof hy2Pool[0]) {
        pthread_mutex_unlock(&hy2PoolLock); errno = EBUSY; return NULL;
    }
    uint8_t addresses[16][16] = {{0}}, lengths[16] = {0};
    size_t count = 0;
    struct addrinfo hints = {0}, *resolved = NULL;
    hints.ai_socktype = SOCK_DGRAM; hints.ai_family = AF_UNSPEC;
    if (MLNetworkResolveHost(node->server, NULL, &hints, &resolved) != 0) {
        pthread_mutex_unlock(&hy2PoolLock); errno = EHOSTUNREACH; return NULL;
    }
    for (struct addrinfo *address = resolved; address && count < 16; address = address->ai_next) {
        if (address->ai_family == AF_INET) {
            memcpy(addresses[count], &((struct sockaddr_in *)address->ai_addr)->sin_addr, 4); lengths[count++] = 4;
        } else if (address->ai_family == AF_INET6) {
            memcpy(addresses[count], &((struct sockaddr_in6 *)address->ai_addr)->sin6_addr, 16); lengths[count++] = 16;
        }
    }
    freeaddrinfo(resolved);
    const char *roots = MLSTREAM_CA_BUNDLE;
#if defined(MLSTREAM_HOST) || defined(MLSTREAM_TEST_CA_OVERRIDE)
    const char *override = getenv("MLSTREAM_CA_FILE");
    if (override && *override) roots = override;
#endif
    hy2_engine_config_t config = {
        .addresses = (const uint8_t (*)[16])addresses, .address_lens = lengths, .address_count = count,
        .port = node->port, .sni = node->sni, .peer_host = node->server, .auth = node->pass,
        .pin_sha256 = node->pin, .obfs_password = node->obfs, .ca_file = roots,
        .connect_timeout_ms = timeout
    };
    if (node->protocol == MLHysteria2 && node->fingerprint[0])
        fprintf(stderr, "MuyuClash: Hysteria2 client-fingerprint is compatibility metadata; QUIC uses its native TLS profile, matching the fixed Mihomo baseline.\n");
    MLHy2Shared *entry = calloc(1, sizeof *entry);
    char reason[300];
    MLTUICConfig tuic = {.quic = config, .alpnLength = node->quicALPNLength, .congestion = node->quicCongestion,
        .heartbeatMS = node->quicHeartbeat, .maxUDPPayload = node->quicMaxPayload, .disableSNI = node->quicDisableSNI};
    memcpy(tuic.uuid, node->uuid, sizeof tuic.uuid); memcpy(tuic.alpn, node->quicALPN, sizeof tuic.alpn);
    if (!entry || !(entry->engine = node->protocol == MLTUICProtocol ? MLTUICStart(&tuic, reason, sizeof reason) : hy2_engine_start(&config, reason, sizeof reason))) {
        free(entry); pthread_mutex_unlock(&hy2PoolLock); errno = EACCES; return NULL;
    }
    entry->node = *node; entry->refs = 1; entry->timeout = timeout; entry->interfaceIndex = MLNetworkInterfaceIndex(); hy2Pool[freeSlot] = entry;
    pthread_mutex_unlock(&hy2PoolLock);
    return entry;
}

static void releaseHy2(MLHy2Shared *entry) {
    if (!entry) return;
    pthread_mutex_lock(&hy2PoolLock);
    if (--entry->refs) { pthread_mutex_unlock(&hy2PoolLock); return; }
    for (size_t i = 0; i < sizeof hy2Pool / sizeof hy2Pool[0]; ++i) if (hy2Pool[i] == entry) hy2Pool[i] = NULL;
    pthread_mutex_unlock(&hy2PoolLock);
    if (entry->node.protocol == MLTUICProtocol) MLTUICStop(entry->engine); else hy2_engine_stop(entry->engine);
    OPENSSL_cleanse(entry, sizeof *entry);
    free(entry);
}

static int waitFD(int fd, short events, uint64_t deadline) {
    for (;;) {
        uint64_t now = nowMS();
        if (now >= deadline) { errno = ETIMEDOUT; return -1; }
        uint64_t remaining = deadline - now;
        struct pollfd entry = {fd, events, 0};
        int status = poll(&entry, 1, remaining > INT_MAX ? INT_MAX : (int)remaining);
        if (status > 0) return 0;
        if (status < 0 && errno != EINTR) return -1;
    }
}

static int connectStream(const char *host, uint16_t port, uint64_t deadline) {
    char service[6];
    snprintf(service, sizeof service, "%u", port);
    struct addrinfo hints = {.ai_flags = AI_NUMERICSERV, .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
    struct addrinfo *addresses = NULL;
    int status = MLNetworkResolveHost(host, service, &hints, &addresses);
    if (status) { if (status != EAI_SYSTEM) errno = EHOSTUNREACH; return -1; }
    int fd = -1;
    int error = EHOSTUNREACH;
    for (struct addrinfo *address = addresses; address; address = address->ai_next) {
        if (nowMS() >= deadline) { error = ETIMEDOUT; break; }
        fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fd >= 0 && MLNetworkBindSocket(fd, address->ai_family) != 0) { int saved = errno; close(fd); fd = -1; errno = saved; continue; }
        if (fd < 0) { error = errno; continue; }
        int one = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one) == 0 &&
            fcntl(fd, F_SETFL, O_NONBLOCK) == 0 && fcntl(fd, F_SETFD, FD_CLOEXEC) == 0) {
            if (connect(fd, address->ai_addr, address->ai_addrlen) == 0) break;
            if (errno == EINPROGRESS && waitFD(fd, POLLOUT, deadline) == 0) {
                socklen_t size = sizeof error;
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0) {
                    if (!error) break;
                    errno = error;
                }
            }
        }
        error = errno;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(addresses);
    if (fd < 0) errno = error;
    return fd;
}

static SSL_CTX *newTLSContext(const char *bundle) {
    SSL_CTX *context = SSL_CTX_new(TLS_client_method());
    if (!context) return NULL;
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION) != 1 ||
        SSL_CTX_load_verify_locations(context, bundle, NULL) != 1) {
        SSL_CTX_free(context);
        return NULL;
    }
    return context;
}

static SSL_CTX *defaultTLSContext;
static void loadDefaultTLSContext(void) { defaultTLSContext = newTLSContext(MLSTREAM_CA_BUNDLE); }

static int tlsFailure(SSL *tls, int result, short *events) {
    int savedError = errno;
    switch (SSL_get_error(tls, result)) {
        case SSL_ERROR_WANT_READ: *events = POLLIN; errno = EAGAIN; return -1;
        case SSL_ERROR_WANT_WRITE: *events = POLLOUT; errno = EAGAIN; return -1;
        case SSL_ERROR_ZERO_RETURN: return 0;
        case SSL_ERROR_SYSCALL: errno = savedError ? savedError : ECONNRESET; return -1;
        default: errno = SSL_get_verify_result(tls) != X509_V_OK ? EACCES : EPROTO; return -1;
    }
}

static int innerBIOCreate(BIO *bio) { BIO_set_init(bio, 1); BIO_set_data(bio, NULL); return 1; }
static int innerBIODestroy(BIO *bio) { if (bio) { BIO_set_data(bio, NULL); BIO_set_init(bio, 0); } return 1; }
static int innerBIORead(BIO *bio, char *data, int length) {
    BIO_clear_retry_flags(bio);
    ssize_t count = MLStreamRead(BIO_get_data(bio), data, (size_t)length);
    if (count < 0 && errno == EAGAIN) BIO_set_retry_read(bio);
    return (int)count;
}
static int innerBIOWrite(BIO *bio, const char *data, int length) {
    BIO_clear_retry_flags(bio);
    ssize_t count = MLStreamWrite(BIO_get_data(bio), data, (size_t)length);
    if (count < 0 && errno == EAGAIN) BIO_set_retry_write(bio);
    return (int)count;
}
static long innerBIOControl(BIO *bio, int command, long number, void *pointer) {
    (void)number; (void)pointer;
    MLStream *inner = BIO_get_data(bio);
    if (command == BIO_CTRL_FLUSH) return MLStreamPump(inner) == 0;
    if (command == BIO_CTRL_PENDING) return MLStreamPendingRead(inner);
    if (command == BIO_CTRL_WPENDING) return MLStreamWritePending(inner);
    return 0;
}
static BIO_METHOD *innerBIOMethod;
static void loadInnerBIOMethod(void) {
    innerBIOMethod = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "MuyuClash layered stream");
    if (!innerBIOMethod) return;
    BIO_meth_set_create(innerBIOMethod, innerBIOCreate);
    BIO_meth_set_destroy(innerBIOMethod, innerBIODestroy);
    BIO_meth_set_read(innerBIOMethod, innerBIORead);
    BIO_meth_set_write(innerBIOMethod, innerBIOWrite);
    BIO_meth_set_ctrl(innerBIOMethod, innerBIOControl);
}
static int attachTLSBIO(MLStream *stream) {
    if (!stream->lower) return SSL_set_fd(stream->tls, stream->fd) == 1 ? 0 : -1;
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, loadInnerBIOMethod);
    if (!innerBIOMethod) return -1;
    BIO *bio = BIO_new(innerBIOMethod);
    if (!bio) return -1;
    BIO_set_data(bio, stream->lower);
    SSL_set_bio(stream->tls, bio, bio);
    return 0;
}
static int waitTLSIO(MLStream *stream, short events, uint64_t deadline) {
    if (!stream->lower) return waitFD(stream->fd, events, deadline);
    if (MLStreamPump(stream->lower) < 0) return -1;
    if ((events & POLLIN) && MLStreamPendingRead(stream->lower)) return 0;
    return waitFD(stream->fd, MLStreamEvents(stream->lower, events & POLLIN, events & POLLOUT), deadline);
}

static int connectTLSRoots(MLStream *stream, const MLNode *node, uint64_t deadline, const char *roots) {
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    SSL_CTX *temporary = roots ? newTLSContext(roots) : NULL;
    if (roots && !temporary) { errno = EACCES; return -1; }
#if defined(MLSTREAM_HOST) || defined(MLSTREAM_TEST_CA_OVERRIDE)
    const char *override = getenv("MLSTREAM_CA_FILE");
    if (!roots && override && *override) temporary = newTLSContext(override);
    if (!roots && override && *override && !temporary) { errno = EACCES; return -1; }
#endif
    if (!temporary) pthread_once(&once, loadDefaultTLSContext);
    SSL_CTX *context = temporary ?: defaultTLSContext;
    if (!context) { errno = EACCES; return -1; }
    stream->tls = SSL_new(context);
    SSL_CTX_free(temporary);
    if (!stream->tls || attachTLSBIO(stream) != 0) { errno = EIO; return -1; }
    const char *host = node->sni[0] ? node->sni : node->server;
    static const unsigned char http11[] = "\x08http/1.1";
    static const unsigned char http2[] = "\x02h2";
    if (node->http2 && SSL_set_alpn_protos(stream->tls, http2, sizeof http2 - 1) != 0) { errno = EIO; return -1; }
    if ((node->protocol == MLHTTP || node->websocket) &&
        SSL_set_alpn_protos(stream->tls, http11, sizeof http11 - 1) != 0) { errno = EIO; return -1; }
    uint8_t address[16];
    BOOL literal = inet_pton(AF_INET, host, address) == 1 || inet_pton(AF_INET6, host, address) == 1;
    if (literal) {
        if (X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(stream->tls), host) != 1) { errno = EINVAL; return -1; }
    } else if (SSL_set_tlsext_host_name(stream->tls, host) != 1 || SSL_set1_host(stream->tls, host) != 1) {
        errno = EINVAL;
        return -1;
    }
    while (nowMS() < deadline) {
        ERR_clear_error();
        errno = 0;
        int result = SSL_connect(stream->tls);
        if (result == 1) return 0;
        short events;
        if (tlsFailure(stream->tls, result, &events) == 0) { errno = ECONNRESET; return -1; }
        if (errno != EAGAIN || waitTLSIO(stream, events, deadline) < 0) return -1;
    }
    errno = ETIMEDOUT;
    return -1;
}

static ssize_t readWire(MLStream *stream, void *data, size_t length) {
    stream->readEvents = POLLIN;
    if (stream->anytls) return MLAnyTLSRead(stream->anytls, data, length);
    if (stream->wireguard) return MLWGRead(stream->wireguard, data, length);
    if (stream->ssh) return MLSSHRead(stream->ssh, data, length, &stream->readEvents);
    if (stream->http2Handle) {
        int count = transport_xhttp_tcp.read(stream->http2Handle, data, MIN(length, INT_MAX));
        if (count >= 0) return count;
        if (count == TRANSPORT_EOF) return 0;
        if (count == TRANSPORT_WANT_WRITE) stream->readEvents = POLLOUT;
        errno = count == TRANSPORT_WANT_READ || count == TRANSPORT_WANT_WRITE ? EAGAIN : EPROTO; return -1;
    }
    if (stream->realityHandle) {
        int count = transport_reality.read(stream->realityHandle, data, MIN(length, INT_MAX));
        if (count >= 0) return count;
        if (count == TRANSPORT_EOF) return 0;
        if (count == TRANSPORT_WANT_WRITE) stream->readEvents = POLLOUT;
        errno = count == TRANSPORT_WANT_READ || count == TRANSPORT_WANT_WRITE ? EAGAIN : ECONNRESET;
        return -1;
    }
    if (stream->hy2Handle) {
        int count = (stream->protocol == MLTUICProtocol ? ml_tuic_transport : transport_hy2).read(stream->hy2Handle, data, MIN(length, INT_MAX));
        if (count >= 0) return count;
        if (count == TRANSPORT_EOF) return 0;
        errno = count == TRANSPORT_WANT_READ ? EAGAIN : ECONNRESET;
        return -1;
    }
    if (stream->vision && stream->vision->downstreamDirect && (!stream->tls || !SSL_pending(stream->tls))) {
        ssize_t count = stream->lower ? MLStreamRead(stream->lower, data, length) : recv(stream->fd, data, length, 0);
        if (count < 0 && errno == EWOULDBLOCK) errno = EAGAIN;
        return count;
    }
    if (stream->tls) {
        ERR_clear_error();
        errno = 0;
        int result = SSL_read(stream->tls, data, (int)MIN(length, INT_MAX));
        return result > 0 ? result : tlsFailure(stream->tls, result, &stream->readEvents);
    }
    if (stream->lower) return MLStreamRead(stream->lower, data, length);
    ssize_t result;
    do { result = recv(stream->fd, data, length, 0); } while (result < 0 && errno == EINTR);
    if (result < 0 && errno == EWOULDBLOCK) errno = EAGAIN;
    return result;
}

static ssize_t writeWire(MLStream *stream, const void *data, size_t length) {
    stream->writeEvents = POLLOUT;
    if (stream->anytls) return MLAnyTLSWrite(stream->anytls, data, length);
    if (stream->wireguard) return MLWGWrite(stream->wireguard, data, length);
    if (stream->ssh) return MLSSHWrite(stream->ssh, data, length, &stream->writeEvents);
    if (stream->http2Handle) {
        int count = MLXHTTPWrite(stream->http2Handle, data, MIN(length, INT_MAX));
        if (count >= 0) return count;
        if (count == TRANSPORT_WANT_READ) stream->writeEvents = POLLIN;
        errno = count == TRANSPORT_WANT_READ || count == TRANSPORT_WANT_WRITE ? EAGAIN : EPROTO; return -1;
    }
    if (stream->realityHandle) {
        int count = stream->vision && stream->vision->upstreamDirect
            ? transport_reality.raw_write(stream->realityHandle, data, MIN(length, INT_MAX))
            : transport_reality.write(stream->realityHandle, data, MIN(length, INT_MAX));
        if (count >= 0) return count;
        if (count == TRANSPORT_WANT_READ) stream->writeEvents = POLLIN;
        errno = count == TRANSPORT_WANT_READ || count == TRANSPORT_WANT_WRITE ? EAGAIN : ECONNRESET;
        return -1;
    }
    if (stream->vision && stream->vision->upstreamDirect) {
        ssize_t count = stream->lower ? MLStreamWrite(stream->lower, data, length) : send(stream->fd, data, length, 0);
        if (count < 0 && errno == EWOULDBLOCK) errno = EAGAIN;
        return count;
    }
    if (stream->hy2Handle) {
        int count = (stream->protocol == MLTUICProtocol ? ml_tuic_transport : transport_hy2).write(stream->hy2Handle, data, MIN(length, INT_MAX));
        if (count >= 0) return count;
        errno = count == TRANSPORT_WANT_WRITE ? EAGAIN : ECONNRESET;
        return -1;
    }
    if (stream->tls) {
        ERR_clear_error();
        errno = 0;
        int result = SSL_write(stream->tls, data, (int)length);
        return result > 0 ? result : tlsFailure(stream->tls, result, &stream->writeEvents);
    }
    if (stream->lower) return MLStreamWrite(stream->lower, data, length);
    ssize_t result;
    do { result = send(stream->fd, data, length, 0); } while (result < 0 && errno == EINTR);
    if (result < 0 && errno == EWOULDBLOCK) errno = EAGAIN;
    return result;
}

static int writeHandshake(MLStream *stream, const uint8_t *data, size_t length, uint64_t deadline) {
    while (length) {
        if (nowMS() >= deadline) { errno = ETIMEDOUT; return -1; }
        ssize_t sent = writeWire(stream, data, length);
        if (sent == 0) { errno = EPIPE; return -1; }
        if (sent < 0) {
            if (errno != EAGAIN || waitTLSIO(stream, stream->writeEvents, deadline) < 0) return -1;
        } else {
            data += sent;
            length -= (size_t)sent;
        }
    }
    return 0;
}

static ssize_t readHandshake(MLStream *stream, uint8_t *data, size_t capacity, uint64_t deadline) {
    while (capacity && nowMS() < deadline) {
        ssize_t received = readWire(stream, data, capacity);
        if (received > 0) return received;
        if (received == 0) { errno = ECONNRESET; return -1; }
        if (errno != EAGAIN || waitTLSIO(stream, stream->readEvents, deadline) < 0) return -1;
    }
    errno = capacity ? ETIMEDOUT : EPROTO;
    return -1;
}

static int retainHandshakeTail(MLStream *stream, const uint8_t *data, size_t length) {
    if (!length) return 0;
    stream->in = malloc(length);
    if (!stream->in) return -1;
    memcpy(stream->in, data, length);
    stream->inLength = length;
    return 0;
}

static int httpStatus(const uint8_t *data, size_t length) {
    if (length < 16 || memcmp(data, "HTTP/1.", 7) || (data[7] != '0' && data[7] != '1') ||
        data[8] != ' ' || (data[12] != ' ' && data[12] != '\r')) return 0;
    int status = 0;
    for (size_t i = 9; i < 12; i++) {
        if (data[i] < '0' || data[i] > '9') return 0;
        status = status * 10 + data[i] - '0';
    }
    return status;
}

static size_t httpHeaderEnd(const uint8_t *data, size_t length, size_t *scan) {
    for (; *scan + 4 <= length; ++*scan) {
        if (!memcmp(data + *scan, "\r\n\r\n", 4)) return *scan + 4;
    }
    return 0;
}

static int httpHeaderValue(const uint8_t *response, size_t length, const char *name,
                           char *value, size_t capacity) {
    size_t nameLength = strlen(name);
    const uint8_t *limit = response + length;
    const uint8_t *start = memchr(response, '\n', length);
    if (!start) return -1;
    int found = 0;
    while (++start < limit) {
        const uint8_t *next = memchr(start, '\n', (size_t)(limit - start));
        if (!next || next == start || next[-1] != '\r') return -1;
        const uint8_t *end = next - 1;
        if (end == start) break;
        const uint8_t *delimiter = memchr(start, ':', (size_t)(end - start));
        if (!delimiter) return -1;
        if ((size_t)(delimiter - start) == nameLength && !strncasecmp((const char *)start, name, nameLength)) {
            if (found) return -1;
            const uint8_t *payload = delimiter + 1;
            while (payload < end && (*payload == ' ' || *payload == '\t')) payload++;
            while (end > payload && (end[-1] == ' ' || end[-1] == '\t')) end--;
            size_t count = (size_t)(end - payload);
            if (count >= capacity || memchr(payload, 0, count)) return -1;
            memcpy(value, payload, count);
            value[count] = 0;
            found = 1;
        }
        start = next;
    }
    return found;
}

static BOOL headerHasToken(char *value, const char *token) {
    char *state = NULL;
    for (char *part = strtok_r(value, ",", &state); part; part = strtok_r(NULL, ",", &state)) {
        while (*part == ' ' || *part == '\t') part++;
        size_t length = strlen(part);
        while (length && (part[length - 1] == ' ' || part[length - 1] == '\t')) part[--length] = 0;
        if (!strcasecmp(part, token)) return YES;
    }
    return NO;
}

static int openWebSocket(MLStream *stream, const MLNode *node, uint64_t deadline) {
    char authority[264];
    if (node->wsHost[0]) {
        snprintf(authority, sizeof authority, "%s", node->wsHost);
    } else {
        const char *host = node->sni[0] ? node->sni : node->server;
        const char *left = strchr(host, ':') ? "[" : "";
        const char *right = *left ? "]" : "";
        if (node->port == (node->tls ? 443 : 80)) snprintf(authority, sizeof authority, "%s%s%s", left, host, right);
        else snprintf(authority, sizeof authority, "%s%s%s:%u", left, host, right, node->port);
    }
    uint8_t nonce[16];
    char key[25];
    if (RAND_bytes(nonce, sizeof nonce) != 1 || EVP_EncodeBlock((uint8_t *)key, nonce, sizeof nonce) != 24) {
        errno = EIO;
        return -1;
    }
    char request[1024];
    int count = snprintf(request, sizeof request,
                         "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                         "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
                         node->wsPath[0] ? node->wsPath : "/", authority, key);
    if (count < 0 || (size_t)count >= sizeof request) { errno = EPROTO; return -1; }
    if (writeHandshake(stream, (uint8_t *)request, (size_t)count, deadline) < 0) return -1;

    uint8_t reply[8192];
    size_t length = 0, scan = 0, end = 0;
    while (!(end = httpHeaderEnd(reply, length, &scan))) {
        ssize_t received = readHandshake(stream, reply + length, sizeof reply - length, deadline);
        if (received < 0) return -1;
        length += (size_t)received;
    }
    char input[61], expected[29], value[256];
    snprintf(input, sizeof input, "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digestLength = 0;
    if (!EVP_Digest(input, sizeof input - 1, digest, &digestLength, EVP_sha1(), NULL) || digestLength != 20 ||
        EVP_EncodeBlock((uint8_t *)expected, digest, (int)digestLength) != 28) { errno = EIO; return -1; }
    if (httpStatus(reply, end) != 101 ||
        httpHeaderValue(reply, end, "Sec-WebSocket-Accept", value, sizeof value) != 1 || strcmp(value, expected) ||
        httpHeaderValue(reply, end, "Upgrade", value, sizeof value) != 1 || !headerHasToken(value, "websocket") ||
        httpHeaderValue(reply, end, "Connection", value, sizeof value) != 1 || !headerHasToken(value, "upgrade") ||
        httpHeaderValue(reply, end, "Sec-WebSocket-Extensions", value, sizeof value) != 0 ||
        httpHeaderValue(reply, end, "Sec-WebSocket-Protocol", value, sizeof value) != 0) {
        errno = EPROTO;
        return -1;
    }
    MLWebSocket *websocket = calloc(1, sizeof *websocket);
    if (!websocket) return -1;
    stream->websocket = websocket;
    websocket->headerNeeded = 2;
    if (length > end) {
        websocket->initialLength = length - end;
        websocket->initial = malloc(websocket->initialLength);
        if (!websocket->initial) return -1;
        memcpy(websocket->initial, reply + end, websocket->initialLength);
    }
    return 0;
}

typedef struct {
    MLStream *stream;
    uint64_t deadline;
} MLUpgradeHandshake;

static int writeUpgradeRequest(void *context, const uint8_t *bytes, size_t length) {
    MLUpgradeHandshake *handshake = context;
    return writeHandshake(handshake->stream, bytes, length, handshake->deadline);
}

static ssize_t readUpgradeResponse(void *context, uint8_t *bytes, size_t capacity) {
    MLUpgradeHandshake *handshake = context;
    return readHandshake(handshake->stream, bytes, capacity, handshake->deadline);
}

static int openWebTransport(MLStream *stream, const MLNode *node, uint64_t deadline) {
    if (!node->httpUpgrade) return openWebSocket(stream, node, deadline);
    const char *authority = node->wsHost;
    char defaultAuthority[sizeof node->server + 2];
    if (!authority[0]) {
        const char *host = node->protocol == MLTrojan && node->sni[0] ? node->sni : node->server;
        if (strchr(host, ':')) snprintf(defaultAuthority, sizeof defaultAuthority, "[%s]", host);
        else snprintf(defaultAuthority, sizeof defaultAuthority, "%s", host);
        authority = defaultAuthority;
    }
    MLUpgradeHandshake handshake = {stream, deadline};
    return MLHTTPUpgradeHandshake(node->wsPath[0] ? node->wsPath : NULL, authority, &handshake,
                                  writeUpgradeRequest, readUpgradeResponse, &stream->upgradeTail, &stream->upgradeLength);
}

static int maskWebSocketFrame(uint8_t *out, uint8_t opcode, const uint8_t *data, size_t size) {
    if (size > UINT16_MAX || ((opcode & 8) && size > 125)) { errno = EINVAL; return -1; }
    uint8_t mask[4];
    if (RAND_bytes(mask, sizeof mask) != 1) { errno = EIO; return -1; }
    size_t prefix = size <= 125 ? 2 : 4;
    if (size) memmove(out + prefix + sizeof mask, data, size);
    out[0] = 0x80 | opcode;
    out[1] = 0x80 | (size <= 125 ? (uint8_t)size : 126);
    if (prefix == 4) {
        out[2] = (uint8_t)(size >> 8);
        out[3] = (uint8_t)size;
    }
    memcpy(out + prefix, mask, sizeof mask);
    for (size_t i = 0; i < size; i++) out[prefix + sizeof mask + i] ^= mask[i % sizeof mask];
    return (int)(prefix + sizeof mask + size);
}

static int readConnectResponse(MLStream *stream, uint64_t deadline) {
    uint8_t reply[8192];
    size_t length = 0, scan = 0;
    for (;;) {
        size_t end = httpHeaderEnd(reply, length, &scan);
        if (end) {
            int status = httpStatus(reply, end);
            if (status >= 200 && status < 300) return retainHandshakeTail(stream, reply + end, length - end);
            if (status < 100 || status >= 200 || status == 101) {
                errno = status == 407 ? EACCES : EPROTO;
                return -1;
            }
            memmove(reply, reply + end, length - end);
            length -= end;
            scan = 0;
            continue;
        }
        ssize_t received = readHandshake(stream, reply + length, sizeof reply - length, deadline);
        if (received < 0) return -1;
        length += (size_t)received;
    }
}

static int openConnect(MLStream *stream, const MLNode *node, const vless_dest_t *dest, uint64_t deadline) {
    uint8_t request[2048], reply[4096];
    size_t requestLength = 0, used = 0;
    if (node->protocol == MLHTTP) {
        http_client_t client;
        hc_init(&client, node->user, node->pass, dest);
        if (hc_make_request(&client, request, sizeof request, &requestLength) != HC_OK) { errno = EPROTO; return -1; }
        if (writeHandshake(stream, request, requestLength, deadline) < 0) return -1;
        return readConnectResponse(stream, deadline);
    }

    socks5_client_t client;
    s5c_init(&client, node->user, node->pass, dest);
    if (s5c_make_request(&client, request, sizeof request, &requestLength) != S5C_OK) { errno = EPROTO; return -1; }
    size_t replyLength = 0;
    for (;;) {
        if (writeHandshake(stream, request, requestLength, deadline) < 0) return -1;
        int state;
        do {
            ssize_t received = readHandshake(stream, reply + replyLength, sizeof reply - replyLength, deadline);
            if (received < 0) return -1;
            replyLength += (size_t)received;
            state = s5c_feed(&client, reply, replyLength, &used, request, sizeof request, &requestLength);
        } while (state == S5C_NEED_MORE);
        if (state != S5C_OK) { errno = state == S5C_ERR_AUTH ? EACCES : EPROTO; return -1; }
        if (client.state == S5C_ST_OPEN) {
            if (node->packet) {
                size_t bound = 0;
                if (readSocksAddress(reply + 3, used - 3, &stream->socksRelay, &bound) != 1 || bound != used - 3) { errno = EPROTO; return -1; }
            }
            return retainHandshakeTail(stream, reply + used, replyLength - used);
        }
        if (node->packet && client.state == S5C_ST_REQ_SENT) {
            static const uint8_t associate[] = {5,3,0,1,0,0,0,0,0,0};
            memcpy(request, associate, sizeof associate); requestLength = sizeof associate;
        }
        if (used != replyLength) { errno = EPROTO; return -1; }
        replyLength = 0;
    }
}

static int openProtocol(MLStream *stream, const MLNode *node, const vless_dest_t *dest, uint64_t deadline) {
    uint8_t header[2048];
    size_t length = 0;
    switch (node->protocol) {
        case MLDirect: return 0;
        case MLAnyTLSProtocol:
        case MLWireGuardProtocol: errno = ENOTSUP; return -1;
        case MLTUICProtocol:
            header[0] = 5; header[1] = 1;
            length = MLTUICAddress(dest, header + 2, sizeof header - 2); if (!length) goto protocolError; length += 2;
            break;
        case MLReject: errno = EACCES; return -1;
        case MLSSHProtocol: {
            MLStream *wire = calloc(1, sizeof *wire); if (!wire) return -1;
            wire->fd = stream->fd; wire->lower = stream->lower; wire->readEvents = POLLIN; wire->writeEvents = POLLOUT;
            stream->lower = wire;
            const char *host = dest->domain; char numeric[46];
            if (dest->atyp != VLESS_ADDR_DOMAIN) { if (!inet_ntop(dest->atyp == VLESS_ADDR_IPV4 ? AF_INET : AF_INET6, dest->host_addr, numeric, sizeof numeric)) return -1; host = numeric; }
            uint64_t now = nowMS(); if (now >= deadline) { errno = ETIMEDOUT; return -1; }
            stream->ssh = MLSSHOpen(wire, node->user, node->pass, node->sshPrivateKey, node->sshPassphrase, node->sshHostKeys, node->sshAlgorithms, host, dest->port, (unsigned)(deadline - now));
            return stream->ssh ? 0 : -1;
        }
        case MLHysteria2: {
            if (hy2_tcp_request_build(dest, header, sizeof header, &length) != HY2_OK ||
                writeHandshake(stream, header, length, deadline) < 0) goto protocolError;
            hy2_tcp_response_t response;
            hy2_tcp_response_init(&response);
            uint8_t reply[4096];
            for (;;) {
                ssize_t count = readHandshake(stream, reply, sizeof reply, deadline);
                if (count <= 0) return -1;
                size_t used = 0;
                int result = hy2_tcp_response_feed(&response, reply, (size_t)count, &used);
                if (result == HY2_NEED_MORE) continue;
                if (result != HY2_OK) { errno = result == HY2_REJECTED ? EACCES : EPROTO; return -1; }
                return retainHandshakeTail(stream, reply + used, (size_t)count - used);
            }
        }
        case MLHTTP:
        case MLSOCKS5: return openConnect(stream, node, dest, deadline);
        case MLSnellProtocol: {
            const char *host = dest->domain;
            char numeric[INET6_ADDRSTRLEN];
            if (dest->atyp != VLESS_ADDR_DOMAIN) {
                host = inet_ntop(dest->atyp == VLESS_ADDR_IPV4 ? AF_INET : AF_INET6,
                                 dest->host_addr, numeric, sizeof numeric);
                if (!host) return -1;
            }
            stream->snell = MLSnellOpen(node->snellVersion, node->snellMode, node->pass, host, dest->port, node->packet);
            if (!stream->snell) return -1;
            size_t pending;
            const uint8_t *request = MLSnellOutput(stream->snell, &pending);
            if (writeHandshake(stream, request, pending, deadline) < 0) return -1;
            MLSnellConsumeOutput(stream->snell, pending);
            if (node->packet && node->snellVersion >= 4) {
                uint8_t wire[1024];
                while (!MLSnellReady(stream->snell)) {
                    ssize_t count = readHandshake(stream, wire, MIN(sizeof wire, MLSnellInputSize(stream->snell)), deadline);
                    if (count < 0 || MLSnellFeed(stream->snell, wire, (size_t)count) < 0) return -1;
                }
            }
            return 0;
        }
        case MLShadowsocksR: {
            stream->ssr = MLSSROpen(node->cipher, node->pass, node->ssrProtocol, node->ssrProtocolParam,
                                     node->ssrObfs, node->ssrObfsParam, node->server, node->port, dest);
            if (!stream->ssr) return -1;
            uint8_t *wire = malloc(ML_SSR_FRAME_LIMIT);
            if (!wire) return -1;
            ssize_t size = MLSSRRequest(stream->ssr, wire, ML_SSR_FRAME_LIMIT);
            int result = size < 0 ? -1 : writeHandshake(stream, wire, (size_t)size, deadline);
            int error = errno;
            OPENSSL_cleanse(wire, ML_SSR_FRAME_LIMIT);
            free(wire);
            errno = error;
            return result;
        }
        case MLTrojan: {
            trojan_client_t client;
            trojan_client_init(&client, node->pass, dest);
            if (trojan_client_build_request(&client, NULL, 0, header, sizeof header, &length) != TR_OK) goto protocolError;
            if (node->packet) header[TROJAN_HEX_LEN + 2] = 3;
            break;
        }
        case MLVLESS: {
            stream->codecSize = sizeof(vless_conn_t);
            stream->codec = malloc(stream->codecSize);
            if (!stream->codec) return -1;
            if (vless_conn_init(stream->codec, node->uuid, dest, node->vision ? "xtls-rprx-vision" : NULL) != VC_OK) goto protocolError;
            if (node->packet) ((vless_conn_t *)stream->codec)->cmd = node->vision ? VLESS_CMD_MUX : VLESS_CMD_UDP;
            if (node->vision) {
                stream->vision = calloc(1, sizeof *stream->vision);
                if (!stream->vision) return -1;
                vision_traffic_init(&stream->vision->traffic);
                vision_wrap_init(&stream->vision->up, node->uuid);
                vision_unpad_init(&stream->vision->down, node->uuid);
                vision_wrap_bind_traffic(&stream->vision->up, &stream->vision->traffic);
                vision_unpad_bind_traffic(&stream->vision->down, &stream->vision->traffic);
                stream->vision->first = 1;
                return 0;
            }
            if (vless_conn_make_request(stream->codec, NULL, 0, header, sizeof header, &length) != VC_OK) goto protocolError;
            break;
        }
        case MLVMess: {
            stream->codecSize = sizeof(vmess_client_t);
            stream->codec = malloc(stream->codecSize);
            if (!stream->codec) return -1;
            if (vmess_client_init(stream->codec, node->uuid, node->cipher, dest, NULL) != VMESS_OK) goto protocolError;
            ((vmess_client_t *)stream->codec)->packet = node->packet;
            if (vmess_client_build_request(stream->codec, NULL, 0, header, sizeof header, &length) != VMESS_OK) goto protocolError;
            break;
        }
        case MLShadowsocks: {
            if (MLSS2022Cipher(node->cipher)) {
                stream->ss2022 = MLSS2022Open(node->cipher, node->pass, dest);
                if (!stream->ss2022) return -1;
                if (MLSS2022Request(stream->ss2022, header, sizeof header, &length) != SS_OK) goto protocolError;
                break;
            }
            stream->codecSize = sizeof(shadowsocks_client_t);
            stream->codec = malloc(stream->codecSize);
            if (!stream->codec) return -1;
            ss_client_init(stream->codec, node->cipher, node->pass, dest);
            if (ss_client_build_request(stream->codec, NULL, 0, header, sizeof header, &length) != SS_OK) goto protocolError;
            break;
        }
    }
    if (stream->websocket) {
        uint8_t frame[sizeof header + ML_WS_HEADER_CAP];
        int size = maskWebSocketFrame(frame, 2, header, length);
        return size < 0 ? -1 : writeHandshake(stream, frame, (size_t)size, deadline);
    }
    return writeHandshake(stream, header, length, deadline);

protocolError:
    errno = EPROTO;
    return -1;
}

static int openHTTP2(MLStream *stream, const MLNode *node) {
    MLStream *wire = calloc(1, sizeof *wire); if (!wire) return -1;
    wire->fd = stream->fd; wire->lower = stream->lower; wire->tls = stream->tls; wire->realityHandle = stream->realityHandle;
    wire->readEvents = POLLIN; wire->writeEvents = POLLOUT;
    stream->lower = wire; stream->tls = NULL; stream->realityHandle = NULL;
    transport_tls_cfg_t options = {.sni = node->sni, .peer_host = node->server, .peer_port = node->port,
        .path = node->http2Path, .xhttp_mode = node->http2Mode, .ws_host = node->http2Host};
    stream->http2Handle = MLXHTTPOpen(wire, &options, node->tls);
    if (!stream->http2Handle) { errno = EPROTO; return -1; } return 0;
}

static MLStream *makeAnyTLSWire(void *context, unsigned timeoutMS) {
    const MLNode *node = context; MLStream *wire = calloc(1, sizeof *wire); if (!wire) return NULL;
    wire->fd = -1; wire->readEvents = POLLIN; wire->writeEvents = POLLOUT;
    uint64_t deadline = nowMS() + timeoutMS; wire->fd = connectStream(node->server, node->port, deadline);
    if (wire->fd < 0 || connectTLSRoots(wire, node, deadline, NULL) < 0) { int error = errno; MLStreamClose(wire); errno = error; return NULL; }
    return wire;
}
static MLStream *openParsedStream(MLNode node, const char *destName, uint16_t port, unsigned timeoutMS) {
    uint64_t deadline = nowMS() + timeoutMS;
    MLStream *stream = NULL;
    vless_dest_t dest;
    if (node.protocol == MLReject) { errno = EACCES; goto fail; }
    if (!destName || !hostAddress(destName, port, &dest)) { errno = EINVAL; goto fail; }
    stream = calloc(1, sizeof *stream);
    if (!stream) goto fail;
    stream->fd = -1;
    stream->protocol = node.protocol;
    stream->readEvents = POLLIN;
    stream->writeEvents = POLLOUT;
    if (node.protocol == MLWireGuardProtocol) {
        stream->wireguard = MLWGOpenJSON(node.rawJSON, destName, port, 0, timeoutMS);
        if (!stream->wireguard) goto fail; stream->fd = MLWGFD(stream->wireguard);
        OPENSSL_cleanse(&node, sizeof node); return stream;
    }
    if (node.protocol == MLAnyTLSProtocol) {
        uint8_t digest[32]; unsigned digestLength = 0, interfaceIndex = MLNetworkInterfaceIndex(); char identity[65];
        MLNode identityNode = node; identityNode.packet = 0;
        EVP_MD_CTX *hash = EVP_MD_CTX_new();
        int good = hash && EVP_DigestInit_ex(hash, EVP_sha256(), NULL) == 1 && EVP_DigestUpdate(hash, &identityNode, sizeof identityNode) == 1 &&
            EVP_DigestUpdate(hash, &interfaceIndex, sizeof interfaceIndex) == 1 && EVP_DigestFinal_ex(hash, digest, &digestLength) == 1 && digestLength == 32;
        OPENSSL_cleanse(&identityNode, sizeof identityNode);
        EVP_MD_CTX_free(hash); if (!good) { errno = EIO; goto fail; }
        for (unsigned i = 0; i < 32; i++) snprintf(identity + i * 2, 3, "%02x", digest[i]);
        stream->anytls = node.packet ? MLAnyTLSOpenUDP(identity, node.pass, &dest, node.idleCheck, node.idleTimeout, node.minIdle, timeoutMS, makeAnyTLSWire, &node) :
            MLAnyTLSOpen(identity, node.pass, &dest, node.idleCheck, node.idleTimeout, node.minIdle, timeoutMS, makeAnyTLSWire, &node);
        if (!stream->anytls) goto fail; stream->fd = MLAnyTLSFD(stream->anytls);
        OPENSSL_cleanse(&node, sizeof node); return stream;
    }
    if (node.protocol == MLHysteria2 || node.protocol == MLTUICProtocol) {
        stream->hy2 = acquireHy2(&node, deadline);
        if (!stream->hy2) goto fail;
        char reason[300];
        stream->fd = node.protocol == MLTUICProtocol ? MLTUICDial(stream->hy2->engine, reason, sizeof reason) : hy2_engine_dial(stream->hy2->engine, reason, sizeof reason);
        if (stream->fd < 0) { errno = ETIMEDOUT; goto fail; }
        stream->hy2Handle = (node.protocol == MLTUICProtocol ? ml_tuic_transport : transport_hy2).open(stream->fd, NULL);
        if (!stream->hy2Handle) { errno = EIO; goto fail; }
    } else {
        stream->fd = connectStream(node.protocol != MLDirect ? node.server : destName, node.protocol != MLDirect ? node.port : port, deadline);
    }
    if (stream->fd < 0) goto fail;
    if (node.reality) {
        transport_tls_cfg_t reality = {.sni = node.sni, .fingerprint = node.fingerprint,
            .reality_pbk = node.publicKey, .reality_sid = node.shortID};
        stream->realityHandle = transport_reality.open(stream->fd, &reality);
        if (!stream->realityHandle) { errno = EACCES; goto fail; }
    }
    if ((!node.reality && node.tls && connectTLSRoots(stream, &node, deadline, NULL) < 0) ||
        (node.http2 && openHTTP2(stream, &node) < 0) ||
        (node.websocket && openWebTransport(stream, &node, deadline) < 0) ||
        openProtocol(stream, &node, &dest, deadline) < 0) goto fail;
    OPENSSL_cleanse(&node, sizeof node);
    return stream;

fail: {
    int error = errno;
    MLStreamClose(stream);
    OPENSSL_cleanse(&node, sizeof node);
    errno = error;
    return NULL;
}
}

MLStream *MLStreamOpen(const char *nodeJSON, const char *destName, uint16_t port, unsigned timeoutMS) {
    MLNode node = {0};
    if (parseJSON(nodeJSON, &node) < 0) { OPENSSL_cleanse(&node, sizeof node); return NULL; }
    if (node.dialer[0]) { OPENSSL_cleanse(&node, sizeof node); errno = ENOTSUP; return NULL; }
    MLStream *stream = openParsedStream(node, destName, port, timeoutMS);
    OPENSSL_cleanse(&node, sizeof node); return stream;
}

MLStream *MLStreamWrapTLS(MLStream *inner, const char *host, const char *roots, unsigned timeoutMS) {
    if (!inner || !host) { errno = EINVAL; return NULL; }
    MLNode node = {0};
    if (strlen(host) >= sizeof node.server) { errno = EINVAL; return NULL; }
    strcpy(node.server, host); node.tls = 1;
    MLStream *stream = calloc(1, sizeof *stream);
    if (!stream) return NULL;
    stream->lower = inner; stream->fd = MLStreamFD(inner);
    stream->readEvents = POLLIN; stream->writeEvents = POLLOUT;
    if (connectTLSRoots(stream, &node, nowMS() + timeoutMS, roots) != 0) {
        int error = errno; stream->lower = NULL; stream->fd = -1; MLStreamClose(stream); errno = error; return NULL;
    }
    return stream;
}

MLStream *MLStreamOpenChain(const char *nodesJSONArray, const char *destName, uint16_t port, unsigned timeoutMS) { @autoreleasepool {
    if (!nodesJSONArray) return MLStreamOpen(NULL, destName, port, timeoutMS);
    size_t size = strnlen(nodesJSONArray, 65536);
    if (!size || size == 65536) { errno = EINVAL; return NULL; }
    id objects = [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:nodesJSONArray length:size] options:0 error:NULL];
    if (![objects isKindOfClass:[NSArray class]] || [objects count] > 16) { errno = EINVAL; return NULL; }
    NSArray *nodes = objects;
    if (!nodes.count) return MLStreamOpen(NULL, destName, port, timeoutMS);
    MLNode parsed[16] = {{0}};
    for (NSUInteger i = 0; i < nodes.count; ++i) {
        if (parseNode(nodes[i], &parsed[i]) || (i && (parsed[i].protocol == MLHysteria2 || parsed[i].protocol == MLTUICProtocol || parsed[i].protocol == MLWireGuardProtocol || parsed[i].protocol == MLAnyTLSProtocol || parsed[i].reality || parsed[i].vision))) {
            OPENSSL_cleanse(parsed, sizeof parsed); errno = ENOTSUP; return NULL;
        }
    }
    uint64_t deadline = nowMS() + timeoutMS;
    NSData *first = [NSJSONSerialization dataWithJSONObject:nodes[0] options:0 error:NULL];
    NSString *json = [[NSString alloc] initWithData:first encoding:NSUTF8StringEncoding];
    MLStream *current = MLStreamOpen(json.UTF8String, nodes.count > 1 ? parsed[1].server : destName,
                                     nodes.count > 1 ? parsed[1].port : port, timeoutMS);
    for (NSUInteger i = 1; current && i < nodes.count; ++i) {
        MLStream *next = calloc(1, sizeof *next);
        if (!next) { MLStreamClose(current); current = NULL; break; }
        next->lower = current; next->fd = MLStreamFD(current); next->protocol = parsed[i].protocol;
        next->readEvents = POLLIN; next->writeEvents = POLLOUT;
        const char *destination = i + 1 < nodes.count ? parsed[i + 1].server : destName;
        uint16_t destinationPort = i + 1 < nodes.count ? parsed[i + 1].port : port;
        vless_dest_t dest;
        if (!hostAddress(destination, destinationPort, &dest) ||
            (parsed[i].tls && connectTLSRoots(next, &parsed[i], deadline, NULL) < 0) ||
            (parsed[i].http2 && openHTTP2(next, &parsed[i]) < 0) ||
            (parsed[i].websocket && openWebTransport(next, &parsed[i], deadline) < 0) ||
            openProtocol(next, &parsed[i], &dest, deadline) < 0) {
            int error = errno; MLStreamClose(next); current = NULL; errno = error; break;
        }
        current = next;
    }
    OPENSSL_cleanse(parsed, sizeof parsed);
    return current;
}}

static BOOL hasFrames(const MLStream *stream) {
    return stream->protocol == MLVMess || stream->protocol == MLShadowsocks || stream->ssr;
}

static int setStreamError(MLStream *stream, int error) {
    stream->permanentError = error;
    errno = error;
    return -1;
}

static ssize_t readWebSocketWire(MLStream *stream, uint8_t *data, size_t length) {
    MLWebSocket *websocket = stream->websocket;
    if (websocket->initial) {
        size_t take = MIN(length, websocket->initialLength - websocket->initialOffset);
        memcpy(data, websocket->initial + websocket->initialOffset, take);
        websocket->initialOffset += take;
        if (websocket->initialOffset == websocket->initialLength) {
            free(websocket->initial);
            websocket->initial = NULL;
        }
        return (ssize_t)take;
    }
    return readWire(stream, data, length);
}

static int startWebSocketFrame(MLStream *stream) {
    MLWebSocket *websocket = stream->websocket;
    const uint8_t *header = websocket->header;
    int final = header[0] & 0x80;
    int opcode = header[0] & 15;
    uint64_t length = header[1] & 127;
    if ((header[0] & 0x70) || (header[1] & 0x80)) return setStreamError(stream, EPROTO);
    if (length >= 126) {
        length = 0;
        for (size_t i = 2; i < websocket->headerNeeded; i++) length = (length << 8) | header[i];
        if ((websocket->headerNeeded == 4 && length < 126) ||
            (websocket->headerNeeded == 10 && (length <= UINT16_MAX || length > INT64_MAX)))
            return setStreamError(stream, EPROTO);
    }
    if (opcode == 0 || opcode == 2) {
        if ((opcode == 0) != websocket->fragmented) return setStreamError(stream, EPROTO);
        websocket->fragmented = !final;
    } else if ((opcode != 8 && opcode != 9 && opcode != 10) || !final || length > 125 ||
               (opcode == 8 && length == 1)) {
        return setStreamError(stream, EPROTO);
    }
    websocket->remaining = length;
    websocket->opcode = (uint8_t)opcode;
    websocket->controlLength = 0;
    return 0;
}

static int queueWebSocketControl(MLStream *stream, uint8_t opcode, const uint8_t *data, size_t length) {
    MLWebSocket *websocket = stream->websocket;
    int frame = maskWebSocketFrame(websocket->reply, opcode, data, length);
    if (frame < 0) return setStreamError(stream, errno);
    websocket->replyOffset = 0;
    websocket->replyLength = (size_t)frame;
    if (opcode == 8) websocket->closeQueued = 1;
    return 0;
}

static ssize_t readWebSocket(MLStream *stream, uint8_t *data, size_t length) {
    MLWebSocket *websocket = stream->websocket;
    for (unsigned steps = 0; steps < 32; steps++) {
        if (websocket->peerClosed) return 0;
        if (websocket->replyLength) {
            if (MLStreamPump(stream) < 0) return -1;
            if (websocket->replyLength) { errno = EAGAIN; return -1; }
        }
        if (websocket->headerLength < websocket->headerNeeded) {
            ssize_t count = readWebSocketWire(stream, websocket->header + websocket->headerLength,
                                              websocket->headerNeeded - websocket->headerLength);
            if (count < 0) return -1;
            if (!count) {
                if (websocket->headerLength || websocket->fragmented) return setStreamError(stream, EPROTO);
                return 0;
            }
            websocket->headerLength += (size_t)count;
            if (websocket->headerLength < websocket->headerNeeded) continue;
            if (websocket->headerNeeded == 2) {
                uint8_t marker = websocket->header[1] & 127;
                websocket->headerNeeded = marker == 127 ? 10 : marker == 126 ? 4 : 2;
                if (websocket->headerNeeded > 2) continue;
            }
            if (startWebSocketFrame(stream) < 0) return -1;
        }
        if (websocket->remaining) {
            BOOL control = (websocket->opcode & 8) != 0;
            size_t readLength = control ? (size_t)websocket->remaining : (size_t)MIN(websocket->remaining, length);
            uint8_t *output = control ? websocket->incomingControl + websocket->controlLength : data;
            ssize_t count = readWebSocketWire(stream, output, readLength);
            if (count < 0) return -1;
            if (!count) return setStreamError(stream, EPROTO);
            websocket->remaining -= (size_t)count;
            if (!control) {
                if (!websocket->remaining) {
                    websocket->headerLength = 0;
                    websocket->headerNeeded = 2;
                }
                return count;
            }
            websocket->controlLength += (size_t)count;
            if (websocket->remaining) continue;
        }
        websocket->headerLength = 0;
        websocket->headerNeeded = 2;
        if (websocket->opcode == 8) {
            websocket->peerClosed = 1;
            stream->writeClosing = 1;
            if (!websocket->closeQueued &&
                queueWebSocketControl(stream, 8, websocket->incomingControl, websocket->controlLength) < 0) return -1;
            return 0;
        }
        if (websocket->opcode == 9 && !websocket->closeQueued &&
            queueWebSocketControl(stream, 10, websocket->incomingControl, websocket->controlLength) < 0) return -1;
    }
    errno = EAGAIN;
    return -1;
}

static ssize_t readTransport(MLStream *stream, void *data, size_t length) {
    if (stream->upgradeTail) {
        size_t take = MIN(length, stream->upgradeLength - stream->upgradeOffset);
        memcpy(data, stream->upgradeTail + stream->upgradeOffset, take);
        stream->upgradeOffset += take;
        if (stream->upgradeOffset == stream->upgradeLength) {
            free(stream->upgradeTail);
            stream->upgradeTail = NULL;
        }
        return (ssize_t)take;
    }
    return stream->websocket ? readWebSocket(stream, data, length) : readWire(stream, data, length);
}

static int decodeFrames(MLStream *stream, const uint8_t *data, size_t length) {
    size_t plain = 0;
    if (stream->protocol == MLVMess) {
        vmess_client_t *client = stream->codec;
        uint16_t before = client->dec_count;
        int result = vmess_client_feed_downstream(client, data, length, stream->in, ML_PLAIN_CAP, &plain);
        if (client->dec_count < before) return setStreamError(stream, EOVERFLOW);
        if (result == VMESS_EOF) stream->readEnded = 1;
        else if (result != VMESS_OK && result != VMESS_NEED_MORE) return setStreamError(stream, EPROTO);
    } else if (stream->ss2022) {
        int result = MLSS2022Feed(stream->ss2022, data, length, stream->in, ML_PLAIN_CAP, &plain);
        if (result != SS_OK && result != SS_NEED_MORE) return setStreamError(stream, EPROTO);
    } else if (stream->ssr) {
        ssize_t count = MLSSRFeed(stream->ssr, data, length, stream->in, ML_PLAIN_CAP);
        if (count < 0) return setStreamError(stream, errno);
        plain = (size_t)count;
    } else {
        shadowsocks_client_t *client = stream->codec;
        int result = ss_client_feed_downstream(client, data, length, stream->in, ML_PLAIN_CAP, &plain);
        if (result != SS_OK && result != SS_NEED_MORE) return setStreamError(stream, EPROTO);
        if (client->dec_salt_received && !CRYPTO_memcmp(client->dec_salt, client->enc_salt, client->salt_len))
            return setStreamError(stream, EPROTO);
    }
    stream->inOffset = 0;
    stream->inLength = plain;
    stream->stagedRead = plain != 0 && !stream->readEnded && !stream->ssr;
    return 0;
}

static ssize_t takeRead(MLStream *stream, void *data, size_t length) {
    size_t take = MIN(length, stream->inLength - stream->inOffset);
    memcpy(data, stream->in + stream->inOffset, take);
    stream->inOffset += take;
    return (ssize_t)take;
}

static ssize_t readFramed(MLStream *stream, void *data, size_t length) {
    if (!stream->in) {
        stream->in = malloc(ML_PLAIN_CAP);
        if (!stream->in) return setStreamError(stream, ENOMEM);
    }
    if (stream->stagedRead && decodeFrames(stream, NULL, 0) < 0) return -1;
    for (unsigned steps = 0; steps < 8; steps++) {
        if (stream->inLength) return takeRead(stream, data, length);
        if (stream->readEnded) return 0;
        uint8_t wire[4096];
        ssize_t count = readTransport(stream, wire, sizeof wire);
        if (count < 0) return errno == EAGAIN ? -1 : setStreamError(stream, errno);
        if (!count) {
            if (stream->protocol == MLVMess) {
                vmess_client_t *codec = stream->codec;
                if (!codec->resp_header_done || codec->dec_stage_len || codec->have_size)
                    return setStreamError(stream, EPROTO);
            } else if (stream->ssr ? !MLSSRComplete(stream->ssr) :
                       stream->ss2022 ? !MLSS2022Complete(stream->ss2022) : ((shadowsocks_client_t *)stream->codec)->dec_stage_len != 0) {
                return setStreamError(stream, EPROTO);
            }
            stream->readEnded = 1;
            return 0;
        }
        if (decodeFrames(stream, wire, (size_t)count) < 0) return -1;
    }
    if (stream->inLength) return takeRead(stream, data, length);
    errno = EAGAIN;
    return -1;
}

static ssize_t readSnell(MLStream *stream, void *data, size_t length) {
    for (unsigned steps = 0; ; steps++) {
        ssize_t count = MLSnellRead(stream->snell, data, length);
        if (count >= 0) {
            if (!count) stream->readEnded = 1;
            return count;
        }
        if (errno == EMSGSIZE) return -1;
        if (errno != EAGAIN) return setStreamError(stream, errno);
        if (steps >= 8) return -1;
        uint8_t wire[4096];
        count = readTransport(stream, wire, MIN(sizeof wire, MLSnellInputSize(stream->snell)));
        if (count < 0) return errno == EAGAIN ? -1 : setStreamError(stream, errno);
        int result = count ? MLSnellFeed(stream->snell, wire, (size_t)count) : MLSnellFinishRead(stream->snell);
        if (result < 0) return setStreamError(stream, errno);
    }
}

static ssize_t readVision(MLStream *stream, void *data, size_t length) {
    MLVision *vision = stream->vision; vless_conn_t *codec = stream->codec;
    if (vision->first) { errno = EAGAIN; return -1; }
    if (!stream->in) { stream->in = malloc(ML_PLAIN_CAP); if (!stream->in) return setStreamError(stream, ENOMEM); }
    for (unsigned steps = 0; steps < 8; ++steps) {
        uint8_t wire[4096]; ssize_t received = readTransport(stream, wire, sizeof wire);
        if (received < 0) return errno == EAGAIN ? -1 : setStreamError(stream, errno);
        if (!received) {
            if (codec->state != VC_ST_OPEN || vision->down.stash_len || vision->down.remaining_content > 0 || vision->down.remaining_padding > 0) return setStreamError(stream, EPROTO);
            stream->readEnded = 1; return 0;
        }
        size_t offset = 0;
        if (codec->state != VC_ST_OPEN) {
            int result = vless_conn_feed_response(codec, wire, (size_t)received, &offset);
            if (result == VC_NEED_MORE) continue;
            if (result != VC_OK || offset > (size_t)received) return setStreamError(stream, EPROTO);
        }
        size_t output = 0; int direct = 0;
        if (vision_unpad(&vision->down, wire + offset, received - offset, stream->in, ML_PLAIN_CAP, &output, &direct)) return setStreamError(stream, EPROTO);
        if (output) vision_filter_tls(&vision->traffic, stream->in, output);
        if (direct) vision->downstreamDirect = 1;
        stream->inLength = output; stream->inOffset = 0;
        if (output) return takeRead(stream, data, length);
    }
    errno = EAGAIN; return -1;
}

ssize_t MLStreamRead(MLStream *stream, void *data, size_t length) {
    if (!length) return 0;
    if (stream->permanentError) { errno = stream->permanentError; return -1; }
    if (stream->inOffset < stream->inLength) return takeRead(stream, data, length);
    if (stream->readEnded) return 0;
    stream->inOffset = 0;
    stream->inLength = 0;
    if (stream->outLength && stream->writeEvents == POLLIN) {
        if (MLStreamPump(stream) < 0) return -1;
        if (stream->outLength && stream->writeEvents == POLLIN) { errno = EAGAIN; return -1; }
    }
    if (stream->snell) return readSnell(stream, data, length);
    if (hasFrames(stream)) return readFramed(stream, data, length);
    if (stream->vision) return readVision(stream, data, length);

    vless_conn_t *codec = stream->protocol == MLVLESS ? stream->codec : NULL;
    size_t take = MIN(length, ML_PLAIN_CAP);
    for (;;) {
        ssize_t received = readTransport(stream, data, take);
        if (received < 0) return errno == EAGAIN ? -1 : setStreamError(stream, errno);
        if (received == 0) {
            if (codec && codec->state != VC_ST_OPEN) return setStreamError(stream, EPROTO);
            stream->readEnded = 1;
            return 0;
        }
        if (!codec || codec->state == VC_ST_OPEN) return received;
        size_t offset = 0;
        int result = vless_conn_feed_response(codec, data, (size_t)received, &offset);
        if (result == VC_NEED_MORE) continue;
        if (result != VC_OK || offset > (size_t)received) return setStreamError(stream, EPROTO);
        size_t remaining = (size_t)received - offset;
        if (remaining) {
            memmove(data, (uint8_t *)data + offset, remaining);
            return (ssize_t)remaining;
        }
    }
}

static int flushOutput(MLStream *stream, const uint8_t *bytes, size_t *offset, size_t *length) {
    while (*offset < *length) {
        if (stream->tls && stream->readEvents == POLLOUT) return 1;
        ssize_t count = writeWire(stream, bytes + *offset, *length - *offset);
        if (count < 0) return errno == EAGAIN ? 1 : setStreamError(stream, errno);
        if (!count) return setStreamError(stream, EPIPE);
        *offset += (size_t)count;
    }
    *offset = 0;
    *length = 0;
    return 0;
}

static uint8_t *outputPayload(MLStream *stream) {
    if (!stream->out) stream->out = malloc(ML_OUTPUT_CAP);
    if (!stream->out) { setStreamError(stream, ENOMEM); return NULL; }
    return stream->out + (stream->websocket ? ML_WS_HEADER_CAP : 0);
}

static int commitOutput(MLStream *stream, uint8_t *payload, size_t length) {
    if (stream->websocket) {
        int size = maskWebSocketFrame(stream->out, 2, payload, length);
        if (size < 0) return setStreamError(stream, errno);
        length = (size_t)size;
    }
    stream->outLength = length;
    return 0;
}

int MLStreamPump(MLStream *stream) {
    if (stream->anytls) {
        if (MLAnyTLSPump(stream->anytls) < 0) return setStreamError(stream, errno);
        if (stream->writeClosing && !stream->writeEnded) { MLAnyTLSShutdown(stream->anytls); stream->writeEnded = 1; }
        return 0;
    }
    if (stream->lower && MLStreamPump(stream->lower) < 0) return setStreamError(stream, errno);
    if (stream->permanentError) { errno = stream->permanentError; return -1; }
    MLWebSocket *websocket = stream->websocket;
    for (;;) {
        int result = flushOutput(stream, stream->out, &stream->outOffset, &stream->outLength);
        if (result) return result < 0 ? -1 : 0;
        if (stream->snell) {
            size_t pending, offset = 0;
            const uint8_t *wire = MLSnellOutput(stream->snell, &pending);
            size_t length = pending;
            result = flushOutput(stream, wire, &offset, &length);
            MLSnellConsumeOutput(stream->snell, result ? offset : pending);
            if (result) return result < 0 ? -1 : 0;
            if (stream->writeClosing && !stream->shutdownFrameQueued) {
                if (MLSnellShutdown(stream->snell) < 0) return setStreamError(stream, errno);
                stream->shutdownFrameQueued = 1;
                continue;
            }
        }
        if (stream->http2Handle && transport_xhttp_tcp.want_write(stream->http2Handle)) {
            if (writeWire(stream, NULL, 0) < 0) return errno == EAGAIN ? 0 : setStreamError(stream, errno);
            if (transport_xhttp_tcp.want_write(stream->http2Handle)) return 0;
        }
        if (stream->realityHandle && transport_reality.want_write(stream->realityHandle)) {
            if (writeWire(stream, NULL, 0) < 0) return errno == EAGAIN ? 0 : setStreamError(stream, errno);
            if (transport_reality.want_write(stream->realityHandle)) return 0;
        }
        if (stream->vision && stream->vision->pendingDirect) {
            if (stream->realityHandle && transport_reality.raw_write(stream->realityHandle, NULL, 0) < 0) return setStreamError(stream, EPROTO);
            stream->vision->pendingDirect = 0; stream->vision->upstreamDirect = 1;
        }
        if (websocket) {
            result = flushOutput(stream, websocket->reply, &websocket->replyOffset, &websocket->replyLength);
            if (result) return result < 0 ? -1 : 0;
        }
        if (!stream->writeClosing || stream->writeEnded) return 0;
        if (stream->protocol == MLVMess && !stream->shutdownFrameQueued && !(websocket && websocket->peerClosed)) {
            stream->shutdownFrameQueued = 1;
            uint8_t *payload = outputPayload(stream);
            if (!payload) return -1;
            size_t length = 0;
            if (vmess_client_encrypt_chunk(stream->codec, (const uint8_t *)"", 0, payload,
                                          ML_TX_CAP, &length) != VMESS_OK) return setStreamError(stream, EPROTO);
            if (commitOutput(stream, payload, length) < 0) return -1;
            continue;
        }
        if (websocket) {
            if (!websocket->closeQueued) {
                if (queueWebSocketControl(stream, 8, NULL, 0) < 0) return -1;
                continue;
            }
            stream->writeEnded = 1;
            return 0;
        }
        break;
    }
    if (stream->ssh) {
        if (MLSSHShutdown(stream->ssh, &stream->writeEvents) < 0) return errno == EAGAIN ? 0 : setStreamError(stream, errno);
    } else if (stream->http2Handle) {
        if (!stream->http2Closing) { stream->http2Closing = 1; transport_xhttp_tcp.shutdown(stream->http2Handle); }
        if (transport_xhttp_tcp.want_write(stream->http2Handle)) return 0;
    } else if (stream->tls && !(stream->vision && stream->vision->upstreamDirect)) {
        if (stream->readEvents == POLLOUT) return 0;
        ERR_clear_error();
        errno = 0;
        int result = SSL_shutdown(stream->tls);
        if (result < 0 && tlsFailure(stream->tls, result, &stream->writeEvents) < 0) {
            if (errno == EAGAIN && (SSL_get_shutdown(stream->tls) & SSL_SENT_SHUTDOWN) &&
                stream->writeEvents == POLLIN) {
                stream->writeEnded = 1;
                return 0;
            }
            return errno == EAGAIN ? 0 : setStreamError(stream, errno);
        }
    } else if (stream->lower) {
        MLStreamShutdownWrite(stream->lower);
    } else if (shutdown(stream->fd, SHUT_WR) < 0 && errno != ENOTCONN) {
        return setStreamError(stream, errno);
    }
    stream->writeEnded = 1;
    return 0;
}

ssize_t MLStreamWrite(MLStream *stream, const void *data, size_t length) {
    if (!length) return 0;
    if (stream->writeClosing) { errno = EPIPE; return -1; }
    if (MLStreamPump(stream) < 0) return -1;
    if (stream->snell) {
        if (MLStreamWritePending(stream)) { errno = EAGAIN; return -1; }
        ssize_t count = MLSnellWrite(stream->snell, data, length);
        if (count < 0) return errno == EAGAIN || errno == EMSGSIZE ? -1 : setStreamError(stream, errno);
        return MLStreamPump(stream) < 0 ? -1 : count;
    }
    if (stream->vision) {
        if (MLStreamWritePending(stream) || stream->readEvents == POLLOUT) { errno = EAGAIN; return -1; }
        uint8_t *payload = outputPayload(stream); if (!payload) return -1;
        size_t take = MIN(length, 4096), offset = 0, encoded = 0;
        if (stream->vision->first) {
            if (vless_conn_make_request(stream->codec, NULL, 0, payload, ML_TX_CAP, &offset) != VC_OK) return setStreamError(stream, EPROTO);
            stream->vision->first = 0;
        }
        int before = stream->vision->up.direct_sent;
        if (vision_wrap(&stream->vision->up, data, take, payload + offset, ML_TX_CAP - offset, &encoded)) return setStreamError(stream, EPROTO);
        if (!before && stream->vision->up.direct_sent) stream->vision->pendingDirect = 1;
        if (commitOutput(stream, payload, offset + encoded) < 0) return -1;
        return MLStreamPump(stream) < 0 ? -1 : (ssize_t)take;
    }
    if (!stream->tls && !stream->websocket && !hasFrames(stream)) {
        ssize_t sent = writeWire(stream, data, length);
        if (sent < 0 && errno != EAGAIN) return setStreamError(stream, errno);
        return sent;
    }
    if (MLStreamWritePending(stream) || stream->readEvents == POLLOUT) { errno = EAGAIN; return -1; }
    uint8_t *payload = outputPayload(stream);
    if (!payload) return -1;
    size_t take = MIN(length, VMESS_CHUNK_PAYLOAD_MAX);
    size_t encoded = 0;
    if (stream->protocol == MLVMess) {
        vmess_client_t *client = stream->codec;
        if (client->enc_count == UINT16_MAX) return setStreamError(stream, EOVERFLOW);
        if (vmess_client_encrypt_chunk(client, data, take, payload, ML_TX_CAP, &encoded) != VMESS_OK)
            return setStreamError(stream, EPROTO);
    } else if (stream->protocol == MLShadowsocks) {
        int status = stream->ss2022 ? MLSS2022Encrypt(stream->ss2022, data, take, payload, ML_TX_CAP, &encoded) : ss_client_encrypt_chunk(stream->codec, data, take, payload, ML_TX_CAP, &encoded);
        if (status != SS_OK)
            return setStreamError(stream, EPROTO);
    } else if (stream->ssr) {
        take = MIN(length, ML_SSR_WRITE_LIMIT);
        ssize_t count = MLSSRWrite(stream->ssr, data, take, payload, ML_TX_CAP);
        if (count < 0) return setStreamError(stream, errno);
        encoded = (size_t)count;
    } else {
        memcpy(payload, data, take);
        encoded = take;
    }
    if (commitOutput(stream, payload, encoded) < 0) return -1;
    return MLStreamPump(stream) < 0 ? -1 : (ssize_t)take;
}

int MLStreamFD(const MLStream *stream) { return stream->fd; }

short MLStreamEvents(const MLStream *stream, int wantRead, int wantWrite) {
    if (stream->permanentError) return 0;
    short events = 0;
    if (wantRead && !stream->readEnded && !(stream->websocket && stream->websocket->replyLength)) events |= stream->readEvents;
    if (MLStreamWritePending(stream))
        events |= stream->readEvents == POLLOUT ? POLLOUT : stream->writeEvents;
    else if (wantWrite && !stream->writeClosing) events |= POLLOUT;
    return stream->lower ? MLStreamEvents(stream->lower, events & POLLIN, events & POLLOUT) : events;
}

int MLStreamPendingRead(const MLStream *stream) {
    if (stream->inOffset < stream->inLength) return 1;
    if (stream->permanentError || stream->readEnded ||
        (stream->outLength && stream->writeEvents == POLLIN) ||
        (stream->websocket && stream->websocket->replyLength)) return 0;
    return (stream->snell && MLSnellPendingRead(stream->snell)) ||
        stream->stagedRead || stream->upgradeTail || (stream->websocket && stream->websocket->initial) ||
        (stream->http2Handle && MLXHTTPPendingRead(stream->http2Handle)) ||
        (stream->tls && SSL_pending(stream->tls) > 0) || (stream->lower && MLStreamPendingRead(stream->lower));
}

int MLStreamWritePending(const MLStream *stream) {
    size_t snellPending;
    return !stream->permanentError && ((stream->snell && MLSnellOutput(stream->snell, &snellPending)) ||
        (stream->http2Handle && transport_xhttp_tcp.want_write(stream->http2Handle)) ||
        (stream->realityHandle && transport_reality.want_write(stream->realityHandle)) ||
        (stream->vision && stream->vision->pendingDirect) || (stream->lower && MLStreamWritePending(stream->lower)) || stream->outLength || (stream->writeClosing && !stream->writeEnded) ||
        (stream->websocket && stream->websocket->replyLength));
}

int MLStreamVisionDirect(const MLStream *stream) {
    if (stream->vision) return stream->vision->upstreamDirect | (stream->vision->downstreamDirect << 1);
    return stream->lower ? MLStreamVisionDirect(stream->lower) : 0;
}

void MLStreamShutdownWrite(MLStream *stream) {
    stream->writeClosing = 1;
    (void)MLStreamPump(stream);
}

void MLStreamClose(MLStream *stream) {
    if (!stream) return;
    SSL_free(stream->tls);
    MLSSHClose(stream->ssh);
    if (stream->anytls) { MLAnyTLSClose(stream->anytls); stream->fd = -1; }
    if (stream->wireguard) { MLWGClose(stream->wireguard); stream->fd = -1; }
    if (stream->http2Handle) transport_xhttp_tcp.close(stream->http2Handle);
    if (stream->realityHandle) transport_reality.close(stream->realityHandle);
    if (stream->hy2Handle) (stream->protocol == MLTUICProtocol ? ml_tuic_transport : transport_hy2).close(stream->hy2Handle);
    if (stream->lower) MLStreamClose(stream->lower);
    else if (stream->fd >= 0) close(stream->fd);
    releaseHy2(stream->hy2);
    if (stream->codec) OPENSSL_cleanse(stream->codec, stream->codecSize);
    if (stream->out) OPENSSL_cleanse(stream->out, ML_OUTPUT_CAP);
    if (stream->websocket) {
        free(stream->websocket->initial);
        free(stream->websocket);
    }
    free(stream->codec);
    MLSS2022Close(stream->ss2022);
    MLSSRClose(stream->ssr);
    MLSnellClose(stream->snell);
    if (stream->vision) OPENSSL_cleanse(stream->vision, sizeof *stream->vision);
    free(stream->vision);
    free(stream->out);
    free(stream->in);
    free(stream->upgradeTail);
    free(stream);
}

struct MLDatagram {
    int fd, pair[2], networkFD, threaded, stopped, failed;
    pthread_t thread;
    MLHy2Shared *hy2; MLHy2UDP *udp;
    MLTUICUDP *tuic;
    MLWGSession *wireguard;
    MLStream *stream;
    MLShadowsocksUDP *shadowsocks;
    MLSS2022 *ss2022;
    MLSSRUDP *ssr;
    vless_dest_t target;
    vless_udp_t framing;
    uint8_t trojanPending[4096]; size_t trojanLength;
};

static int datagramFailure(MLDatagram *session, int error) {
    __sync_lock_test_and_set(&session->failed, error);
    (void)send(session->pair[1], "", 0, 0); return -1;
}

static int datagramPair(MLDatagram *session) {
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, session->pair)) return -1;
    int bufferSize = 65536;
    for (size_t i = 0; i < 2; ++i) {
        if (setsockopt(session->pair[i], SOL_SOCKET, SO_SNDBUF, &bufferSize, sizeof bufferSize) ||
            setsockopt(session->pair[i], SOL_SOCKET, SO_RCVBUF, &bufferSize, sizeof bufferSize) ||
            fcntl(session->pair[i], F_SETFL, O_NONBLOCK) || fcntl(session->pair[i], F_SETFD, FD_CLOEXEC)) {
            int error = errno; close(session->pair[0]); close(session->pair[1]); session->pair[0] = session->pair[1] = -1; errno = error; return -1;
        }
    }
    session->fd = session->pair[0]; return 0;
}

static size_t socksAddress(const vless_dest_t *target, uint8_t *out) {
    size_t pos = 0;
    if (target->atyp == VLESS_ADDR_IPV4) { out[pos++] = 1; memcpy(out + pos, target->host_addr, 4); pos += 4; }
    else if (target->atyp == VLESS_ADDR_IPV6) { out[pos++] = 4; memcpy(out + pos, target->host_addr, 16); pos += 16; }
    else { size_t length = strlen(target->domain); out[pos++] = 3; out[pos++] = length; memcpy(out + pos, target->domain, length); pos += length; }
    out[pos++] = target->port >> 8; out[pos++] = target->port; return pos;
}

static int connectDatagramSocket(const char *host, uint16_t port) {
    struct addrinfo hints = {0}, *addresses = NULL; char service[6]; snprintf(service, sizeof service, "%u", port);
    hints.ai_socktype = SOCK_DGRAM; hints.ai_family = AF_UNSPEC;
    if (MLNetworkResolveHost(host, service, &hints, &addresses)) { errno = EHOSTUNREACH; return -1; }
    int result = -1;
    for (struct addrinfo *address = addresses; address; address = address->ai_next) {
        int fd = socket(address->ai_family, SOCK_DGRAM, 0);
        if (fd < 0) continue;
        if (MLNetworkBindSocket(fd, address->ai_family) || fcntl(fd, F_SETFL, O_NONBLOCK) ||
            fcntl(fd, F_SETFD, FD_CLOEXEC) || connect(fd, address->ai_addr, address->ai_addrlen)) { close(fd); continue; }
        result = fd; break;
    }
    freeaddrinfo(addresses); return result;
}

static void *socksDatagramThread(void *context) {
    MLDatagram *session = context; uint8_t upload[1800]; size_t uploadSize = 0;
    while (!__sync_fetch_and_add(&session->stopped, 0)) {
        if (MLStreamPump(session->stream)) { datagramFailure(session, errno); break; }
        uint8_t control; ssize_t count = MLStreamRead(session->stream, &control, 1);
        if (!count || count > 0 || (count < 0 && errno != EAGAIN)) { datagramFailure(session, count > 0 ? EPROTO : ECONNRESET); break; }
        if (!uploadSize) {
            uint8_t packet[1501]; count = recv(session->pair[1], packet, sizeof packet, 0);
            if (count > 0) {
                if (count > 1500) { datagramFailure(session, EMSGSIZE); break; }
                memset(upload, 0, 3); size_t header = 3 + socksAddress(&session->target, upload + 3);
                memcpy(upload + header, packet, count); uploadSize = header + count;
            } else if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { datagramFailure(session, errno); break; }
        }
        if (uploadSize) {
            count = send(session->networkFD, upload, uploadSize, 0);
            if (count == uploadSize) uploadSize = 0;
            else if (count >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) { datagramFailure(session, count >= 0 ? EIO : errno); break; }
        }
        for (unsigned burst = 0; burst < 8; ++burst) {
            uint8_t wire[1800]; count = recv(session->networkFD, wire, sizeof wire, 0);
            if (count < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) break;
                datagramFailure(session, errno); goto complete;
            }
            vless_dest_t source; size_t header = 0;
            if (count < 4 || wire[0] || wire[1] || wire[2] || readSocksAddress(wire + 3, count - 3, &source, &header) != 1 ||
                source.atyp != session->target.atyp || source.port != session->target.port || memcmp(source.host_addr, session->target.host_addr, sizeof source.host_addr) ||
                count <= 3 + header || count - 3 - header > 1500) { datagramFailure(session, EPROTO); goto complete; }
            (void)send(session->pair[1], wire + 3 + header, count - 3 - header, 0);
        }
        struct pollfd descriptors[3] = {
            {session->pair[1], uploadSize ? 0 : POLLIN, 0},
            {session->networkFD, POLLIN | (uploadSize ? POLLOUT : 0), 0},
            {MLStreamFD(session->stream), MLStreamEvents(session->stream, 1, 0), 0}
        };
        if (poll(descriptors, 3, 250) < 0 && errno != EINTR) { datagramFailure(session, errno); break; }
    }
complete: return NULL;
}

static int trojanDatagramFeed(MLDatagram *session, const uint8_t *data, size_t size) {
    if (size > sizeof session->trojanPending - session->trojanLength) return datagramFailure(session, EPROTO);
    memcpy(session->trojanPending + session->trojanLength, data, size); session->trojanLength += size;
    while (session->trojanLength) {
        uint8_t *frame = session->trojanPending; size_t address = 0;
        if (frame[0] == 1) address = 7;
        else if (frame[0] == 4) address = 19;
        else if (frame[0] == 3) { if (session->trojanLength < 2) return 0; if (!frame[1]) return datagramFailure(session, EPROTO); address = 4 + frame[1]; }
        else return datagramFailure(session, EPROTO);
        if (session->trojanLength < address + 4) return 0;
        size_t payload = ((size_t)frame[address] << 8) | frame[address + 1];
        if (!payload || payload > 1500 || frame[address + 2] != '\r' || frame[address + 3] != '\n') return datagramFailure(session, EPROTO);
        size_t total = address + 4 + payload; if (session->trojanLength < total) return 0;
        uint8_t expected[260]; size_t expectedSize = socksAddress(&session->target, expected);
        if (address != expectedSize || memcmp(frame, expected, address)) return datagramFailure(session, EPROTO);
        (void)send(session->pair[1], frame + address + 4, payload, 0);
        memmove(frame, frame + total, session->trojanLength - total); session->trojanLength -= total;
    }
    return 0;
}

static int streamDatagramFeed(MLDatagram *session, const uint8_t *data, size_t size) {
    if (session->stream->protocol == MLTrojan) return trojanDatagramFeed(session, data, size);
    size_t offset = 0;
    while (offset < size) {
        size_t used = 0, length = 0; const uint8_t *payload = NULL; vless_dest_t source;
        int result = vless_udp_feed(&session->framing, data + offset, size - offset, &used, &payload, &length, &source);
        offset += used;
        if (result == VLESS_UDP_OK) {
            if (source.atyp != session->target.atyp || source.port != session->target.port || memcmp(source.host_addr, session->target.host_addr, sizeof source.host_addr)) return datagramFailure(session, EPROTO);
            (void)send(session->pair[1], payload, length, 0);
        } else if (result == VLESS_UDP_END) return datagramFailure(session, ECONNRESET);
        else if (result != VLESS_UDP_NEED_MORE && result != VLESS_UDP_SKIPPED) return datagramFailure(session, EPROTO);
        if (!used) break;
    }
    return 0;
}

static void *streamDatagramThread(void *context) {
    MLDatagram *session = context; MLStream *stream = session->stream;
    uint8_t upload[1800]; size_t uploadLength = 0, uploadOffset = 0;
    while (!__sync_fetch_and_add(&session->stopped, 0)) {
        if (MLStreamPump(stream) < 0) { datagramFailure(session, errno); break; }
        if (uploadOffset < uploadLength) {
            ssize_t sent = MLStreamWrite(stream, upload + uploadOffset, uploadLength - uploadOffset);
            if (sent > 0) uploadOffset += sent;
            else if (sent < 0 && errno != EAGAIN) { datagramFailure(session, errno); break; }
        }
        if (uploadOffset == uploadLength && !MLStreamWritePending(stream)) {
            uint8_t packet[1501]; ssize_t n = recv(session->pair[1], packet, sizeof packet, 0);
            if (n > 0) {
                uploadOffset = 0;
                if (n > 1500) { datagramFailure(session, EMSGSIZE); break; }
                if (stream->protocol == MLVMess || stream->snell) { memcpy(upload, packet, n); uploadLength = n; }
                else if (stream->protocol == MLTrojan) {
                    size_t header = socksAddress(&session->target, upload);
                    upload[header++] = n >> 8; upload[header++] = n;
                    upload[header++] = '\r'; upload[header++] = '\n'; memcpy(upload + header, packet, n); uploadLength = header + n;
                } else if (vless_udp_encode(&session->framing, packet, n, upload, sizeof upload, &uploadLength) != VLESS_UDP_OK) { datagramFailure(session, EPROTO); break; }
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { datagramFailure(session, errno); break; }
        }
        uint8_t incoming[1500];
        for (size_t burst = 0; burst < 8; ++burst) {
            ssize_t n = MLStreamRead(stream, incoming, stream->snell ? sizeof incoming : 512);
            if (n > 0) {
                if (stream->snell) (void)send(session->pair[1], incoming, (size_t)n, 0);
                else if (streamDatagramFeed(session, incoming, n)) goto complete;
            }
            else if (!n) { datagramFailure(session, ECONNRESET); goto complete; }
            else if (stream->snell && errno == EMSGSIZE) continue;
            else if (errno != EAGAIN) { datagramFailure(session, errno); goto complete; }
            else break;
        }
        struct pollfd descriptors[2] = {
            {session->pair[1], uploadOffset == uploadLength && !MLStreamWritePending(stream) ? POLLIN : 0, 0},
            {MLStreamFD(stream), MLStreamEvents(stream, 1, uploadOffset < uploadLength), 0}
        };
        if (!MLStreamPendingRead(stream) && poll(descriptors, 2, 250) < 0 && errno != EINTR) { datagramFailure(session, errno); break; }
    }
complete:
    return NULL;
}
MLDatagram *MLDatagramOpen(const char *nodeJSON, const char *destName, uint16_t port, unsigned timeoutMS) {
    MLNode node = {0}; vless_dest_t dest;
    if (!destName || !hostAddress(destName, port, &dest)) { errno = EINVAL; return NULL; }
    if (parseJSON(nodeJSON, &node) < 0) { OPENSSL_cleanse(&node, sizeof node); return NULL; }
    if (node.protocol == MLReject) { OPENSSL_cleanse(&node, sizeof node); errno = EACCES; return NULL; }
    if (node.dialer[0]) { OPENSSL_cleanse(&node, sizeof node); errno = ENOTSUP; return NULL; }
    if ((node.protocol == MLSnellProtocol || node.protocol == MLShadowsocksR) && !node.udpEnabled) {
        OPENSSL_cleanse(&node, sizeof node); errno = ENOTSUP; return NULL;
    }
    MLDatagram *session = calloc(1, sizeof *session); if (!session) return NULL; session->fd = session->pair[0] = session->pair[1] = session->networkFD = -1;
    if (node.protocol == MLWireGuardProtocol) {
        if (!(session->wireguard = MLWGOpenJSON(node.rawJSON, destName, port, 1, timeoutMS))) goto failed;
        session->fd = MLWGFD(session->wireguard);
    } else if (node.protocol == MLSOCKS5) {
        if (dest.atyp == VLESS_ADDR_DOMAIN) { errno = ENOTSUP; goto failed; }
        node.packet = 1; session->target = dest;
        if (!(session->stream = openParsedStream(node, destName, port, timeoutMS))) goto failed;
        vless_dest_t *relay = &session->stream->socksRelay; char host[256];
        if (relay->atyp == VLESS_ADDR_DOMAIN) strcpy(host, relay->domain);
        else {
            uint8_t zero[16] = {0};
            if (!memcmp(relay->host_addr, zero, sizeof zero)) {
                struct sockaddr_storage address; socklen_t size = sizeof address;
                if (getpeername(MLStreamFD(session->stream), (struct sockaddr *)&address, &size)) goto failed;
                const void *bytes = address.ss_family == AF_INET ? (const void *)&((struct sockaddr_in *)&address)->sin_addr :
                                    address.ss_family == AF_INET6 ? (const void *)&((struct sockaddr_in6 *)&address)->sin6_addr : NULL;
                if (!bytes || !inet_ntop(address.ss_family, bytes, host, sizeof host)) goto failed;
            }
            else if (!inet_ntop(relay->atyp == VLESS_ADDR_IPV4 ? AF_INET : AF_INET6, relay->host_addr, host, sizeof host)) goto failed;
        }
        session->networkFD = connectDatagramSocket(host, relay->port);
        if (session->networkFD < 0 || datagramPair(session)) goto failed;
        int result = pthread_create(&session->thread, NULL, socksDatagramThread, session);
        if (result) { errno = result; goto failed; } session->threaded = 1;
    } else if (node.protocol == MLVLESS || node.protocol == MLVMess || node.protocol == MLTrojan ||
               node.protocol == MLAnyTLSProtocol || node.protocol == MLSnellProtocol) {
        if (dest.atyp == VLESS_ADDR_DOMAIN && node.protocol != MLSnellProtocol) { errno = ENOTSUP; goto failed; }
        node.packet = 1; session->target = dest;
        if ((node.protocol != MLSnellProtocol &&
             vless_udp_init(&session->framing, node.vision ? VLESS_UDP_XUDP : VLESS_UDP_LENGTH, &dest) != VLESS_UDP_OK) ||
            !(session->stream = openParsedStream(node, destName, port, timeoutMS)) || datagramPair(session)) goto failed;
        int result = pthread_create(&session->thread, NULL, streamDatagramThread, session);
        if (result) { errno = result; goto failed; }
        session->threaded = 1;
    } else if (nodeJSON && node.protocol == MLTUICProtocol) {
        session->hy2 = acquireHy2(&node, nowMS() + timeoutMS);
        if (!session->hy2 || !(session->tuic = MLTUICUDPOpen(session->hy2->engine, &dest, node.quicReliableUDP))) goto failed;
        session->fd = MLTUICUDPFD(session->tuic);
    } else if (nodeJSON && node.protocol == MLHysteria2) {
        uint64_t deadline = nowMS() + timeoutMS;
        session->hy2 = acquireHy2(&node, deadline);
        if (!session->hy2 || MLHy2WaitReady(session->hy2->engine, timeoutMS) < 0) goto failed;
        char address[320];
        if (hy2_address_text(&dest, address, sizeof address) != HY2_OK || !(session->udp = MLHy2UDPOpen(session->hy2->engine, address))) goto failed;
        session->fd = MLHy2UDPFD(session->udp);
    } else if (node.protocol == MLDirect || node.protocol == MLShadowsocks || node.protocol == MLShadowsocksR) {
        if (node.protocol == MLShadowsocks) {
            if (MLSS2022Cipher(node.cipher)) { if (!(session->ss2022 = MLSS2022Open(node.cipher, node.pass, &dest))) goto failed; }
            else if (!(session->shadowsocks = MLShadowsocksUDPOpen(node.cipher, node.pass, &dest))) goto failed;
        } else if (node.protocol == MLShadowsocksR) {
            session->ssr = MLSSRUDPOpen(node.cipher, node.pass, node.ssrProtocol, node.ssrProtocolParam, &dest);
            if (!session->ssr) goto failed;
        }
        session->fd = node.protocol == MLDirect ? connectDatagramSocket(destName, port) :
                      connectDatagramSocket(node.server, node.port);
        if (session->fd < 0) goto failed;
    } else {
        errno = ENOTSUP;
        goto failed;
    }
    OPENSSL_cleanse(&node, sizeof node); return session;
failed: {
    int error = errno; MLDatagramClose(session); OPENSSL_cleanse(&node, sizeof node); errno = error; return NULL;
}
}
ssize_t MLDatagramRead(MLDatagram *session, void *data, size_t length) {
    if (session->udp) return MLHy2UDPReceive(session->udp, data, length);
    if (session->tuic) return MLTUICUDPReceive(session->tuic, data, length);
    if (session->wireguard) return MLWGRead(session->wireguard, data, length);
    if (session->shadowsocks || session->ss2022 || session->ssr) {
        uint8_t wire[4096]; ssize_t count = recv(session->fd, wire, sizeof wire, 0);
        if (count < 0) { if (errno == EWOULDBLOCK) errno = EAGAIN; return -1; }
        if (session->ssr) return MLSSRUDPDecode(session->ssr, wire, (size_t)count, data, length);
        return session->ss2022 ? MLSS2022UDPDecode(session->ss2022, wire, count, data, length) : MLShadowsocksUDPDecode(session->shadowsocks, wire, count, data, length);
    }
    int error = __sync_fetch_and_add(&session->failed, 0); if (error) { errno = error; return -1; }
    struct iovec vector = {data, length}; struct msghdr message = {0};
    message.msg_iov = &vector; message.msg_iovlen = 1;
    ssize_t count = recvmsg(session->fd, &message, 0);
    if (count < 0 && errno == EWOULDBLOCK) errno = EAGAIN;
    if (count >= 0 && (message.msg_flags & MSG_TRUNC)) { errno = EMSGSIZE; return -1; }
    return count;
}
ssize_t MLDatagramWrite(MLDatagram *session, const void *data, size_t length) {
    if (session->udp) return MLHy2UDPSend(session->udp, data, length);
    if (session->tuic) return MLTUICUDPSend(session->tuic, data, length);
    if (session->wireguard) return MLWGWrite(session->wireguard, data, length);
    if (session->shadowsocks || session->ss2022 || session->ssr) {
        uint8_t wire[2048];
        ssize_t count = session->ssr ? MLSSRUDPEncode(session->ssr, data, length, wire, sizeof wire) :
                        session->ss2022 ? MLSS2022UDPEncode(session->ss2022, data, length, wire, sizeof wire) :
                        MLShadowsocksUDPEncode(session->shadowsocks, data, length, wire, sizeof wire);
        if (count < 0) return -1;
        ssize_t sent = send(session->fd, wire, count, 0);
        if (sent < 0) { if (errno == EWOULDBLOCK) errno = EAGAIN; return -1; }
        if (sent != count) { errno = EIO; return -1; } return length;
    }
    int error = __sync_fetch_and_add(&session->failed, 0); if (error) { errno = error; return -1; }
    if (session->stream && (!length || length > 1500)) { errno = EMSGSIZE; return -1; }
    ssize_t count = send(session->fd, data, length, 0); if (count < 0 && errno == EWOULDBLOCK) errno = EAGAIN; return count;
}
int MLDatagramFD(const MLDatagram *session) { return session->fd; }
void MLDatagramClose(MLDatagram *session) {
    if (!session) return;
    if (session->threaded) { __sync_lock_test_and_set(&session->stopped, 1); (void)send(session->pair[0], "", 0, 0); pthread_join(session->thread, NULL); }
    MLStreamClose(session->stream);
    MLShadowsocksUDPClose(session->shadowsocks);
    MLSS2022Close(session->ss2022);
    MLSSRUDPClose(session->ssr);
    if (session->udp) MLHy2UDPClose(session->udp); else if (session->tuic) MLTUICUDPClose(session->tuic); else if (session->wireguard) MLWGClose(session->wireguard); else if (session->fd >= 0) close(session->fd);
    if (session->pair[1] >= 0) close(session->pair[1]);
    if (session->networkFD >= 0) close(session->networkFD);
    releaseHy2(session->hy2); free(session);
}
