/* Shadowsocks 2022: mandatory AES methods, optional ChaCha20, and session UDP.
   All authentication is completed before plaintext/replay state is committed. */
#include "MLSS2022.h"
#include "blake3.h"
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define WINDOW 8192
#define WIRE_CAP 73728
#define PLAIN_CAP 65535
typedef struct {
    uint8_t id[8], bits[WINDOW / 8];
    uint64_t highest;
    time_t last;
    int active;
} MLSS2022Peer;
struct MLSS2022 {
    int method, header, gotSalt, haveLength;
    size_t keyLength, addressLength, wireLength, plainLength, plainOffset, nextLength;
    uint8_t master[32], encKey[32], decKey[32], encSalt[32], encNonce[12], decNonce[12];
    uint8_t address[259], *wire, *plain;
    uint8_t session[8], udpKey[32];
    uint64_t packet;
    MLSS2022Peer peers[2];
};
static uint16_t read16(const uint8_t *p) { return ((uint16_t)p[0] << 8) | p[1]; }
static void write16(uint8_t *p, size_t v) { p[0] = v >> 8; p[1] = v; }
static uint64_t read64(const uint8_t *p) { uint64_t n = 0; for (unsigned i=0;i<8;i++) n = (n << 8) | p[i]; return n; }
static void write64(uint8_t *p, uint64_t n) { for (unsigned i=0;i<8;i++) { p[7-i] = n; n >>= 8; } }
static int validTime(const uint8_t *p) { uint64_t now = (uint64_t)time(NULL), n = read64(p); return n > now ? n - now <= 30 : now - n <= 30; }
static int advance(uint8_t n[12]) { for (unsigned i=0;i<12;i++) if (++n[i]) return 0; return -1; }
int MLSS2022Cipher(const char *method) {
    if (!method) return 0;
    if (!strcmp(method,"2022-blake3-aes-128-gcm")) return 1;
    if (!strcmp(method,"2022-blake3-aes-256-gcm")) return 2;
    if (!strcmp(method,"2022-blake3-chacha20-poly1305")) return 3;
    return 0;
}
static int decodeKey(int method, const char *password, uint8_t key[32]) {
    size_t n = method == 1 ? 16 : 32, encoded = n == 16 ? 24 : 44;
    if (!method || !password || strlen(password) != encoded) return -1;
    for (size_t i=0;i<encoded;i++) {
        unsigned char c = password[i];
        if (i >= encoded - (n == 16 ? 2 : 1)) { if (c != '=') return -1; }
        else if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/')) return -1;
    }
    uint8_t decoded[48], canonical[48];
    int size = EVP_DecodeBlock(decoded, (const unsigned char *)password, encoded);
    int good = size == (int)(encoded / 4 * 3) && EVP_EncodeBlock(canonical, decoded, n) == (int)encoded && !memcmp(canonical,password,encoded);
    if (good) memcpy(key,decoded,n);
    OPENSSL_cleanse(decoded,sizeof decoded); OPENSSL_cleanse(canonical,sizeof canonical); return good ? 0 : -1;
}
int MLSS2022ValidKey(const char *method, const char *password) {
    uint8_t key[32]; int good = !decodeKey(MLSS2022Cipher(method),password,key); OPENSSL_cleanse(key,sizeof key); return good;
}
static void subkey(MLSS2022 *s, const uint8_t *salt, size_t length, uint8_t key[32]) {
    uint8_t material[64]; memcpy(material,s->master,s->keyLength); memcpy(material+s->keyLength,salt,length);
    const char context[] = "shadowsocks 2022 session subkey";
    blake3_derive_key(context,sizeof context-1,material,s->keyLength+length,key); OPENSSL_cleanse(material,sizeof material);
}
static const EVP_CIPHER *cipher(int method) { return method == 1 ? EVP_aes_128_gcm() : method == 2 ? EVP_aes_256_gcm() : EVP_chacha20_poly1305(); }
static int aead(int method, const uint8_t *key, const uint8_t *nonce, const uint8_t *in, size_t n, uint8_t *out, uint8_t tag[16], int seal) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); if (!c) return -1; int length = 0, tail = 0;
    int good = EVP_CipherInit_ex(c,cipher(method),NULL,NULL,NULL,seal) == 1 && EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_AEAD_SET_IVLEN,12,NULL) == 1 && EVP_CipherInit_ex(c,NULL,NULL,key,nonce,seal) == 1;
    if (!seal) good = good && EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_AEAD_SET_TAG,16,tag) == 1;
    good = good && EVP_CipherUpdate(c,out,&length,in,(int)n) == 1 && EVP_CipherFinal_ex(c,out+length,&tail) == 1 && length+tail == (int)n;
    if (seal) good = good && EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_AEAD_GET_TAG,16,tag) == 1;
    EVP_CIPHER_CTX_free(c); return good ? 0 : -1;
}
static int sealTCP(MLSS2022 *s, const uint8_t *in, size_t n, uint8_t *out) {
    return aead(s->method,s->encKey,s->encNonce,in,n,out,out+n,1) || advance(s->encNonce) ? -1 : 0;
}
static int openTCP(MLSS2022 *s, const uint8_t *in, size_t n, uint8_t *out) {
    return aead(s->method,s->decKey,s->decNonce,in,n,out,(uint8_t *)in+n,0) || advance(s->decNonce) ? -1 : 0;
}
MLSS2022 *MLSS2022Open(const char *method, const char *password, const vless_dest_t *dest) {
    MLSS2022 *s = calloc(1,sizeof *s); if (!s) return NULL; s->method = MLSS2022Cipher(method); s->keyLength = s->method == 1 ? 16 : 32;
    if (!dest || !dest->port || decodeKey(s->method,password,s->master)) { errno = EINVAL; goto bad; }
    size_t n;
    if (dest->atyp == VLESS_ADDR_IPV4 || dest->atyp == VLESS_ADDR_IPV6) { n = dest->atyp == VLESS_ADDR_IPV4 ? 4 : 16; s->address[0] = n == 4 ? 1 : 4; memcpy(s->address+1,dest->host_addr,n); n++; }
    else if (dest->atyp == VLESS_ADDR_DOMAIN && (n = strnlen(dest->domain,256)) > 0 && n <= 255) { s->address[0] = 3; s->address[1] = n; memcpy(s->address+2,dest->domain,n); n += 2; }
    else { errno = EINVAL; goto bad; }
    write16(s->address+n,dest->port); s->addressLength = n+2;
    if (RAND_bytes(s->encSalt,s->keyLength) != 1 || RAND_bytes(s->session,8) != 1) { errno = EIO; goto bad; }
    subkey(s,s->encSalt,s->keyLength,s->encKey); subkey(s,s->session,8,s->udpKey); return s;
bad: MLSS2022Close(s); return NULL;
}
int MLSS2022Request(MLSS2022 *s, uint8_t *wire, size_t cap, size_t *length) {
    uint8_t fixed[11], variable[1161], random[2]; if (RAND_bytes(random,2) != 1) return SS_ERR_CRYPTO;
    size_t padding = read16(random) % 900 + 1, variableLength = s->addressLength+2+padding;
    if (cap < s->keyLength+27+variableLength+16) return SS_ERR_ARG;
    fixed[0] = 0; write64(fixed+1,time(NULL)); write16(fixed+9,variableLength);
    memcpy(variable,s->address,s->addressLength); write16(variable+s->addressLength,padding);
    if (RAND_bytes(variable+s->addressLength+2,padding) != 1) return SS_ERR_CRYPTO;
    memcpy(wire,s->encSalt,s->keyLength);
    int bad = sealTCP(s,fixed,11,wire+s->keyLength) || sealTCP(s,variable,variableLength,wire+s->keyLength+27);
    OPENSSL_cleanse(variable,sizeof variable); if (bad) return SS_ERR_CRYPTO;
    *length = s->keyLength+27+variableLength+16; return SS_OK;
}
int MLSS2022Encrypt(MLSS2022 *s, const uint8_t *data, size_t n, uint8_t *wire, size_t cap, size_t *length) {
    if (!n || n > 65535 || cap < n+34) return SS_ERR_ARG; uint8_t size[2]; write16(size,n);
    if (sealTCP(s,size,2,wire) || sealTCP(s,data,n,wire+18)) return SS_ERR_CRYPTO;
    *length = n+34; return SS_OK;
}
static void consume(MLSS2022 *s, size_t n) { memmove(s->wire,s->wire+n,s->wireLength-n); s->wireLength -= n; }
int MLSS2022Feed(MLSS2022 *s, const uint8_t *wire, size_t n, uint8_t *data, size_t cap, size_t *length) {
    *length = 0; if (n > WIRE_CAP-s->wireLength) return SS_ERR_ARG;
    if (!s->wire) s->wire = malloc(WIRE_CAP);
    if (!s->plain) s->plain = malloc(PLAIN_CAP);
    if (!s->wire || !s->plain) return SS_ERR_ARG;
    if (n) { memcpy(s->wire+s->wireLength,wire,n); s->wireLength += n; }
    if (!s->gotSalt) {
        size_t fixed = 11+s->keyLength;
        if (s->wireLength < s->keyLength+fixed+16) return SS_NEED_MORE;
        uint8_t header[43]; subkey(s,s->wire,s->keyLength,s->decKey); consume(s,s->keyLength);
        if (openTCP(s,s->wire,fixed,header)) return SS_ERR_BAD_TAG;
        if (header[0] != 1 || !validTime(header+1) || CRYPTO_memcmp(header+9,s->encSalt,s->keyLength)) return SS_ERR_BAD_TAG;
        s->nextLength = read16(header+9+s->keyLength); s->haveLength = 1; s->header = s->gotSalt = 1; consume(s,fixed+16);
    }
    while (*length < cap) {
        if (s->plainOffset < s->plainLength) {
            size_t take = s->plainLength-s->plainOffset; if (take > cap-*length) take = cap-*length;
            memcpy(data+*length,s->plain+s->plainOffset,take); s->plainOffset += take; *length += take;
            if (s->plainOffset < s->plainLength) break;
            OPENSSL_cleanse(s->plain,s->plainLength); s->plainOffset = s->plainLength = 0;
        }
        if (!s->haveLength) {
            if (s->wireLength < 18) break; uint8_t size[2];
            if (openTCP(s,s->wire,2,size)) return SS_ERR_BAD_TAG;
            s->nextLength = read16(size); s->haveLength = 1; consume(s,18);
        }
        if (!s->nextLength) return SS_ERR_ARG;
        if (s->wireLength < s->nextLength+16) break;
        if (openTCP(s,s->wire,s->nextLength,s->plain)) return SS_ERR_BAD_TAG;
        s->plainLength = s->nextLength; consume(s,s->nextLength+16); s->haveLength = 0;
    }
    return *length ? SS_OK : SS_NEED_MORE;
}
int MLSS2022Complete(const MLSS2022 *s) { return s->header && !s->wireLength && !s->haveLength && s->plainLength == s->plainOffset; }

static int block(MLSS2022 *s, const uint8_t in[16], uint8_t out[16], int seal) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); if (!c) return -1; int n=0,t=0;
    int good = EVP_CipherInit_ex(c,s->method == 1 ? EVP_aes_128_ecb() : EVP_aes_256_ecb(),NULL,s->master,NULL,seal) == 1 && EVP_CIPHER_CTX_set_padding(c,0) == 1 && EVP_CipherUpdate(c,out,&n,in,16) == 1 && EVP_CipherFinal_ex(c,out+n,&t) == 1 && n+t == 16;
    EVP_CIPHER_CTX_free(c); return good ? 0 : -1;
}
/* RFC 8439 HChaCha20 core for the standard XChaCha20 nonce extension. */
static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24; }
static void put32(uint8_t *p,uint32_t n) { for (unsigned i=0;i<4;i++) { p[i]=n; n >>= 8; } }
static uint32_t rotate(uint32_t n,unsigned bits) { return n<<bits | n>>(32-bits); }
#define QR(a,b,c,d) do { a+=b;d=rotate(d^a,16);c+=d;b=rotate(b^c,12);a+=b;d=rotate(d^a,8);c+=d;b=rotate(b^c,7); } while(0)
static void hchacha(const uint8_t key[32],const uint8_t nonce[16],uint8_t out[32]) {
    uint32_t x[16] = {0x61707865,0x3320646e,0x79622d32,0x6b206574};
    for(unsigned i=0;i<8;i++)x[i+4]=le32(key+i*4);for(unsigned i=0;i<4;i++)x[i+12]=le32(nonce+i*4);
    for(unsigned i=0;i<10;i++){QR(x[0],x[4],x[8],x[12]);QR(x[1],x[5],x[9],x[13]);QR(x[2],x[6],x[10],x[14]);QR(x[3],x[7],x[11],x[15]);QR(x[0],x[5],x[10],x[15]);QR(x[1],x[6],x[11],x[12]);QR(x[2],x[7],x[8],x[13]);QR(x[3],x[4],x[9],x[14]);}
    for(unsigned i=0;i<4;i++){put32(out+i*4,x[i]);put32(out+(i+4)*4,x[i+12]);}OPENSSL_cleanse(x,sizeof x);
}
ssize_t MLSS2022UDPEncode(MLSS2022 *s,const uint8_t *data,size_t n,uint8_t *wire,size_t cap) {
    size_t prefix=s->method==3?24:16,offset=s->method==3?16:0,length=offset+11+s->addressLength+n;
    if(!n||n>1500||cap<prefix+length+16){errno=EMSGSIZE;return -1;}if(s->packet==UINT64_MAX){errno=EOVERFLOW;return -1;}
    uint8_t plain[1800],header[16],key[32],nonce[12]={0}; memcpy(header,s->session,8);write64(header+8,s->packet++);
    if(s->method==3){memcpy(plain,header,16);if(RAND_bytes(wire,24)!=1)goto bad;hchacha(s->master,wire,key);memcpy(nonce+4,wire+16,8);}
    else{if(block(s,header,wire,1))goto bad;memcpy(key,s->udpKey,32);memcpy(nonce,header+4,12);}
    plain[offset]=0;write64(plain+offset+1,time(NULL));write16(plain+offset+9,0);memcpy(plain+offset+11,s->address,s->addressLength);memcpy(plain+offset+11+s->addressLength,data,n);
    int result=aead(s->method,key,nonce,plain,length,wire+prefix,wire+prefix+length,1);OPENSSL_cleanse(key,sizeof key);OPENSSL_cleanse(plain,sizeof plain);
    if(!result)return prefix+length+16;
bad:OPENSSL_cleanse(key,sizeof key);OPENSSL_cleanse(plain,sizeof plain);errno=EIO;return -1;
}
static int replay(const MLSS2022Peer *p,uint64_t id) {
    if(!p->active||id>p->highest)return 0;
    return p->highest-id>=WINDOW || (p->bits[(id%WINDOW)/8] & (1u << (id%8))) != 0;
}
static void remember(MLSS2022Peer *p,uint64_t id) {
    if(!p->active || (id>p->highest && id-p->highest>=WINDOW))memset(p->bits,0,sizeof p->bits);
    else if(id>p->highest)for(uint64_t d=1;d<=id-p->highest;d++){uint64_t n=p->highest+d;p->bits[(n%WINDOW)/8]&=~(1u<<(n%8));}
    if(!p->active||id>p->highest)p->highest=id;p->bits[(id%WINDOW)/8]|=1u<<(id%8);p->active=1;p->last=time(NULL);
}
ssize_t MLSS2022UDPDecode(MLSS2022 *s,const uint8_t *wire,size_t n,uint8_t *data,size_t cap) {
    size_t prefix=s->method==3?24:16,offset=s->method==3?16:0;
    if(n<=prefix+offset+19+16||n>4096){errno=EPROTO;return -1;}size_t length=n-prefix-16;
    uint8_t plain[4096],header[16],key[32],nonce[12]={0};if(length>sizeof plain){errno=EMSGSIZE;return -1;}
    if(s->method==3){hchacha(s->master,wire,key);memcpy(nonce+4,wire+16,8);}
    else{if(block(s,wire,header,0))goto denied;subkey(s,header,8,key);memcpy(nonce,header+4,12);}
    if(aead(s->method,key,nonce,wire+prefix,length,plain,(uint8_t *)wire+n-16,0))goto denied;
    if(s->method==3)memcpy(header,plain,16);
    if(length<offset+19||plain[offset]!=1||!validTime(plain+offset+1)||CRYPTO_memcmp(plain+offset+9,s->session,8))goto denied;
    size_t padding=read16(plain+offset+17),pos=offset+19+padding;
    if(pos>length||s->addressLength>length-pos||memcmp(plain+pos,s->address,s->addressLength))goto denied;
    pos+=s->addressLength;size_t payload=length-pos;if(!payload||payload>1500){errno=EMSGSIZE;goto bad;}
    uint64_t id=read64(header+8);MLSS2022Peer *p=NULL;
    for(unsigned i=0;i<2;i++)if(s->peers[i].active&&!CRYPTO_memcmp(s->peers[i].id,header,8)){p=&s->peers[i];break;}
    if(p&&replay(p,id))goto denied;
    if(!p){
        if(!s->peers[0].active)p=&s->peers[0];
        else if(!s->peers[1].active)p=&s->peers[1];
        else{unsigned old=s->peers[0].last<s->peers[1].last?0:1;if(time(NULL)-s->peers[old].last<60)goto denied;p=&s->peers[old];}
        memset(p,0,sizeof *p);memcpy(p->id,header,8);
    }
    remember(p,id);if(payload>cap){errno=EMSGSIZE;goto bad;}memcpy(data,plain+pos,payload);OPENSSL_cleanse(key,sizeof key);OPENSSL_cleanse(plain,sizeof plain);return payload;
denied:errno=EACCES;
bad:OPENSSL_cleanse(key,sizeof key);OPENSSL_cleanse(plain,sizeof plain);return -1;
}
void MLSS2022Close(MLSS2022 *s){if(!s)return;if(s->wire){OPENSSL_cleanse(s->wire,WIRE_CAP);free(s->wire);}if(s->plain){OPENSSL_cleanse(s->plain,PLAIN_CAP);free(s->plain);}OPENSSL_cleanse(s,sizeof *s);free(s);}
