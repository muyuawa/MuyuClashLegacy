#import "MLMRS.h"
#define ZSTD_STATIC_LINKING_ONLY
#include "../.deps/providers/zstd-1.5.7/lib/zstd.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

static const NSUInteger MLMRSCompressedLimit=8*1024*1024, MLMRSDecodedLimit=4*1024*1024, MLMRSRuleLimit=10000;
static id MLMRSError(NSError **error, NSString *message) {
    if (error) *error=[NSError errorWithDomain:@"E_PROVIDER_MRS" code:1 userInfo:@{NSLocalizedDescriptionKey:message}];
    return nil;
}
typedef struct { const unsigned char *bytes; size_t length, cursor; } MLMRSReader;
static BOOL MLMRSBytes(MLMRSReader *reader, void *destination, size_t count) {
    if (reader->cursor>reader->length || count>reader->length-reader->cursor) return NO;
    if (destination) memcpy(destination,reader->bytes+reader->cursor,count);
    reader->cursor+=count; return YES;
}
static BOOL MLMRSUInt64(MLMRSReader *reader, uint64_t *result) {
    unsigned char bytes[8]; if (!MLMRSBytes(reader,bytes,8)) return NO;
    uint64_t value=0; for (unsigned i=0;i<8;++i) value=(value<<8)|bytes[i]; *result=value; return YES;
}
static NSData *MLMRSInflate(NSData *compressed, NSError **error) {
    if (!compressed.length || compressed.length>MLMRSCompressedLimit) return MLMRSError(error,@"The compressed MRS exceeds its size limit.");
    ZSTD_DStream *decoder=ZSTD_createDStream();
    if (!decoder) return MLMRSError(error,@"Cannot allocate the bounded MRS decoder.");
    size_t code=ZSTD_initDStream(decoder);
    if (!ZSTD_isError(code)) code=ZSTD_DCtx_setMaxWindowSize(decoder,MLMRSDecodedLimit);
    if (ZSTD_isError(code)) { ZSTD_freeDStream(decoder); return MLMRSError(error,@"Cannot configure the bounded MRS decoder."); }
    ZSTD_inBuffer input={compressed.bytes,compressed.length,0}; NSMutableData *decoded=[NSMutableData data]; unsigned char buffer[16384];
    for (;;) {
        size_t before=input.pos; ZSTD_outBuffer output={buffer,sizeof buffer,0};
        code=ZSTD_decompressStream(decoder,&output,&input);
        if (ZSTD_isError(code) || output.pos>MLMRSDecodedLimit-decoded.length || (input.pos==before && !output.pos && code)) {
            ZSTD_freeDStream(decoder); return MLMRSError(error,@"The MRS frame is corrupt, truncated or exceeds its decoding budget.");
        }
        [decoded appendBytes:buffer length:output.pos];
        if (!code) {
            BOOL exact=input.pos==input.size; ZSTD_freeDStream(decoder);
            return exact ? decoded : MLMRSError(error,@"Unexpected data follows the MRS frame.");
        }
    }
}
static uint64_t *MLMRSWords(MLMRSReader *reader, size_t *length) {
    uint64_t count; if (!MLMRSUInt64(reader,&count) || !count || count>MLMRSDecodedLimit/8 || count>(reader->length-reader->cursor)/8) return NULL;
    uint64_t *words=calloc((size_t)count,sizeof(*words)); if (!words) return NULL;
    for (size_t i=0;i<(size_t)count;++i) if (!MLMRSUInt64(reader,&words[i])) { free(words); return NULL; }
    *length=(size_t)count; return words;
}
static unsigned MLMRSBit(const uint64_t *words, size_t bit) { return (unsigned)((words[bit/64]>>(bit%64))&1); }
static NSString *MLMRSReverseUnicode(NSString *text) {
    NSMutableString *result=[NSMutableString string];
    for (NSInteger i=(NSInteger)text.length-1;i>=0;--i) {
        unichar c=[text characterAtIndex:(NSUInteger)i];
        if (c>=0xdc00 && c<=0xdfff && i>0) {
            unichar high=[text characterAtIndex:(NSUInteger)i-1];
            if (high>=0xd800 && high<=0xdbff) { unichar pair[2]={high,c}; [result appendString:[NSString stringWithCharacters:pair length:2]]; --i; continue; }
        }
        [result appendString:[NSString stringWithCharacters:&c length:1]];
    }
    return result;
}
static NSArray *MLMRSDomains(MLMRSReader *reader, NSUInteger declaredCount, NSError **error) {
    unsigned char version; if (!MLMRSBytes(reader,&version,1) || version!=1) return MLMRSError(error,@"The MRS domain-set version is unsupported.");
    size_t leafCount=0, bitmapCount=0; uint64_t *leaves=MLMRSWords(reader,&leafCount), *bitmap=MLMRSWords(reader,&bitmapCount);
    uint64_t count=0; unsigned char *labels=NULL, *edges=NULL; uint32_t *parents=NULL; NSArray *result=nil;
    NSMutableSet *keys=nil; NSMutableArray *domains=nil;
    if (!leaves || !bitmap || !MLMRSUInt64(reader,&count) || !count || count>MLMRSDecodedLimit || count>reader->length-reader->cursor) goto invalid;
    size_t nodeCount=(size_t)count+1, bitCount=nodeCount+(size_t)count;
    if (leafCount!=(nodeCount+63)/64 || bitmapCount!=(bitCount+63)/64) goto invalid;
    labels=malloc((size_t)count); edges=calloc(nodeCount,1); parents=calloc(nodeCount,sizeof(*parents));
    if (!labels || !edges || !parents || !MLMRSBytes(reader,labels,(size_t)count)) goto invalid;
    size_t bit=0, edge=0;
    for (size_t node=0;node<nodeCount;++node) {
        unsigned previous=0; BOOL hadChild=NO;
        while (bit<bitCount && !MLMRSBit(bitmap,bit)) {
            if (edge>=(size_t)count || edge+1<=node || (hadChild && labels[edge]<=previous)) goto invalid;
            previous=labels[edge]; hadChild=YES; parents[edge+1]=(uint32_t)node; edges[edge+1]=labels[edge]; ++edge; ++bit;
        }
        if (bit>=bitCount) goto invalid;
        ++bit;
    }
    if (edge!=(size_t)count || bit!=bitCount || MLMRSBit(leaves,0)) goto invalid;
    for (size_t i=nodeCount;i<leafCount*64;++i) if (MLMRSBit(leaves,i)) goto invalid;
    for (size_t i=bitCount;i<bitmapCount*64;++i) if (MLMRSBit(bitmap,i)) goto invalid;
    keys=[NSMutableSet set];
    for (size_t node=1;node<nodeCount;++node) if (MLMRSBit(leaves,node)) {
        unsigned char path[1024]; size_t length=0, cursor=node;
        while (cursor) {
            if (length>=sizeof path || parents[cursor]>=cursor) goto invalid;
            path[length++]=edges[cursor]; cursor=parents[cursor];
        }
        for (size_t i=0;i<length/2;++i) { unsigned char value=path[i]; path[i]=path[length-1-i]; path[length-1-i]=value; }
        NSString *reverse=[[NSString alloc] initWithBytes:path length:length encoding:NSUTF8StringEncoding];
        NSString *domain=reverse ? MLMRSReverseUnicode(reverse) : nil;
        if (!domain.length || domain.length>255 || [domain rangeOfCharacterFromSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]].location!=NSNotFound ||
            [domain rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location!=NSNotFound) goto invalid;
        [keys addObject:domain];
        if (keys.count>declaredCount*2 || keys.count>MLMRSRuleLimit*2) goto invalid;
    }
    domains=[NSMutableArray array];
    for (NSString *key in [keys.allObjects sortedArrayUsingSelector:@selector(compare:)]) {
        if ([key hasPrefix:@"+."]) {
            NSString *base=[key substringFromIndex:2];
            [domains addObject:[keys containsObject:base] ? key : [@"." stringByAppendingString:base]];
        } else if (![keys containsObject:[@"+." stringByAppendingString:key]]) [domains addObject:key];
    }
    if (!domains.count || domains.count>MLMRSRuleLimit) goto invalid;
    result=[domains copy]; goto done;
invalid:
    result=MLMRSError(error,@"The MRS domain trie is malformed or exceeds its rule budget.");
done:
    free(leaves); free(bitmap); free(labels); free(edges); free(parents); return result;
}
static BOOL MLMRSMapped(const unsigned char address[16]) {
    static const unsigned char prefix[12]={0,0,0,0,0,0,0,0,0,0,0xff,0xff}; return memcmp(address,prefix,12)==0;
}
static NSArray *MLMRSIPRanges(MLMRSReader *reader, NSError **error) {
    unsigned char version; uint64_t count;
    if (!MLMRSBytes(reader,&version,1) || version!=1 || !MLMRSUInt64(reader,&count) || !count || count>MLMRSRuleLimit || count>(reader->length-reader->cursor)/32) return MLMRSError(error,@"The MRS IP-range header is invalid.");
    NSMutableArray *prefixes=[NSMutableArray array]; unsigned char previous[16]={0}; BOOL hadPrevious=NO, previousIPv4=NO;
    for (NSUInteger index=0;index<(NSUInteger)count;++index) {
        unsigned char from[16],to[16];
        if (!MLMRSBytes(reader,from,16) || !MLMRSBytes(reader,to,16) || memcmp(from,to,16)>0 || MLMRSMapped(from)!=MLMRSMapped(to)) return MLMRSError(error,@"The MRS contains invalid or overlapping IP intervals.");
        BOOL ipv4=MLMRSMapped(from);
        // netip sorts IPv4 before IPv6, even IPv6 ::/128 which precedes the
        // mapped IPv4 bytes in a raw 128-bit comparison.
        if (hadPrevious && ((!previousIPv4 && ipv4) || (previousIPv4==ipv4 && memcmp(from,previous,16)<=0))) return MLMRSError(error,@"The MRS contains invalid or overlapping IP intervals.");
        memcpy(previous,to,16); hadPrevious=YES; previousIPv4=ipv4;
        for (;;) {
            unsigned trailing=0;
            for (int bit=127;bit>=0 && !(from[bit/8]&(1u<<(7-bit%8)));--bit) ++trailing;
            unsigned prefix=128-trailing; if (ipv4 && prefix<96) prefix=96;
            unsigned char end[16];
            for (;;) {
                memcpy(end,from,16);
                for (unsigned bit=prefix;bit<128;++bit) end[bit/8]|=(unsigned char)(1u<<(7-bit%8));
                if (memcmp(end,to,16)<=0) break;
                ++prefix;
            }
            char text[INET6_ADDRSTRLEN];
            if (!inet_ntop(ipv4 ? AF_INET : AF_INET6,ipv4 ? from+12 : from,text,sizeof text)) return MLMRSError(error,@"Cannot represent an MRS IP prefix.");
            [prefixes addObject:[NSString stringWithFormat:@"%s/%u",text,ipv4 ? prefix-96 : prefix]];
            if (prefixes.count>MLMRSRuleLimit) return MLMRSError(error,@"The expanded MRS exceeds 10000 IP prefixes.");
            if (!memcmp(end,to,16)) break;
            memcpy(from,end,16);
            for (int byte=15;byte>=0;--byte) if (++from[byte]) break;
        }
    }
    return [prefixes copy];
}
NSArray *MLMRSDecode(NSData *compressed, NSString *behavior, NSError **error) {
    if (error) *error=nil;
    if (![@[@"domain",@"ipcidr"] containsObject:behavior]) return MLMRSError(error,@"Mihomo MRSv1 supports only domain and IP-prefix behavior.");
    NSData *decoded=MLMRSInflate(compressed,error); if (!decoded) return nil;
    MLMRSReader reader={decoded.bytes,decoded.length,0}; unsigned char header[4],kind; uint64_t count,extra;
    if (!MLMRSBytes(&reader,header,4) || memcmp(header,"MRS\1",4) || !MLMRSBytes(&reader,&kind,1) ||
        kind!=([behavior isEqual:@"domain"] ? 0 : 1) || !MLMRSUInt64(&reader,&count) || !count || count>MLMRSRuleLimit ||
        !MLMRSUInt64(&reader,&extra) || extra>MLMRSDecodedLimit || !MLMRSBytes(&reader,NULL,(size_t)extra)) return MLMRSError(error,@"The MRSv1 header is invalid or incompatible with this Provider.");
    NSArray *rules=kind==0 ? MLMRSDomains(&reader,(NSUInteger)count,error) : MLMRSIPRanges(&reader,error);
    if (rules && reader.cursor!=reader.length) return MLMRSError(error,@"Unexpected data follows the MRS rule table.");
    return rules;
}
