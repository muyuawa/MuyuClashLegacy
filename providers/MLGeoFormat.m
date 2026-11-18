#import "MLGeoFormat.h"
#include <maxminddb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

static const NSUInteger MLGeoLimit=32*1024*1024;
static id MLGFail(NSError **error, NSString *code, NSString *reason) {
    if (error) *error=[NSError errorWithDomain:code code:1 userInfo:@{NSLocalizedDescriptionKey:reason}]; return nil;
}
NSString *MLGeoNormalizedKey(NSString *kind, NSString *operand) {
    NSString *key=[operand stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    if ([kind isEqual:@"asn"]) return [key.uppercaseString hasPrefix:@"AS"] ? [key substringFromIndex:2] : key;
    return key.lowercaseString;
}
static NSString *MLGBase(NSString *key) { return [key hasPrefix:@"!"] ? [key substringFromIndex:1] : key; }
typedef struct { const unsigned char *bytes; size_t length, cursor; NSUInteger *budget; } MLGProto;
static BOOL MLGVarint(MLGProto *r, uint64_t *out) {
    uint64_t value=0;
    for (unsigned shift=0;shift<70;shift+=7) {
        if (r->cursor>=r->length) return NO;
        unsigned char byte=r->bytes[r->cursor++];
        if (shift==63 && (byte&0xfe)) return NO;
        value|=(uint64_t)(byte&127)<<shift;
        if (!(byte&128)) { *out=value; return YES; }
    }
    return NO;
}
static BOOL MLGField(MLGProto *r, unsigned *field, unsigned *wire, MLGProto *slice, uint64_t *value) {
    uint64_t tag=0, length=0;
    if (++*r->budget>4000000 || !MLGVarint(r,&tag) || !tag || tag>>3>0x1fffffff) return NO;
    *field=(unsigned)(tag>>3); *wire=(unsigned)(tag&7); slice->bytes=NULL; slice->length=0; slice->cursor=0; slice->budget=r->budget;
    if (*wire==0) return MLGVarint(r,value);
    if (*wire==2) { if (!MLGVarint(r,&length) || length>r->length-r->cursor) return NO; }
    else if (*wire==1) length=8;
    else if (*wire==5) length=4;
    else return NO;
    if (length>r->length-r->cursor) return NO;
    slice->bytes=r->bytes+r->cursor; slice->length=(size_t)length; r->cursor+=(size_t)length; return YES;
}
static NSString *MLGText(MLGProto *slice, NSUInteger limit) {
    if (!slice->length || slice->length>limit) return nil;
    NSString *text=[[NSString alloc] initWithBytes:slice->bytes length:slice->length encoding:NSUTF8StringEncoding];
    return [text rangeOfCharacterFromSet:[NSCharacterSet controlCharacterSet]].location==NSNotFound ? text : nil;
}
static BOOL MLGAppendRange(NSMutableData *data, unsigned family, const unsigned char *address, unsigned prefix) {
    unsigned bits=family==4 ? 32 : 128;
    if ((family!=4 && family!=6) || prefix>bits || data.length>MLGeoLimit-33) return NO;
    unsigned char range[33]={0}; range[0]=(unsigned char)family;
    memcpy(range+1,address,bits/8); memcpy(range+17,address,bits/8);
    for (unsigned bit=prefix;bit<bits;++bit) { range[1+bit/8]&=(unsigned char)~(1u<<(7-bit%8)); range[17+bit/8]|=(unsigned char)(1u<<(7-bit%8)); }
    [data appendBytes:range length:sizeof range]; return YES;
}
static int MLGRangeCompare(const void *a, const void *b) { return memcmp(a,b,33); }
static BOOL MLGAdjacent(const unsigned char *end, const unsigned char *start, unsigned family) {
    unsigned char increment[16]; memcpy(increment,end,16); int last=family==4 ? 3 : 15;
    for (int i=last;i>=0;--i) if (++increment[i]) return memcmp(increment,start,16)>=0;
    return NO;
}
static NSData *MLGMergeRanges(NSMutableData *input) {
    qsort(input.mutableBytes,input.length/33,33,MLGRangeCompare);
    NSMutableData *output=[NSMutableData data]; const unsigned char *bytes=input.bytes;
    for (NSUInteger i=0;i<input.length;i+=33) {
        const unsigned char *range=bytes+i;
        if (output.length) {
            unsigned char *previous=(unsigned char *)output.mutableBytes+output.length-33;
            if (previous[0]==range[0] && (memcmp(range+1,previous+17,16)<=0 || MLGAdjacent(previous+17,range+1,range[0]))) {
                if (memcmp(range+17,previous+17,16)>0) memcpy(previous+17,range+17,16); continue;
            }
        }
        [output appendBytes:range length:33];
    }
    return [output copy];
}
static NSDictionary *MLGSet(NSString *kind, NSString *key, NSData *payload, NSUInteger count, BOOL inverse) {
    return @{@"kind":kind,@"key":key,@"payload":payload,@"count":@(count),@"inverse":@(inverse)};
}
static BOOL MLGDomain(MLGProto message, unsigned *type, NSString **value, NSSet **attributes) {
    *type=0; *value=nil; NSMutableSet *attrs=[NSMutableSet set]; unsigned field,wire; uint64_t integer; MLGProto slice;
    while (message.cursor<message.length) {
        if (!MLGField(&message,&field,&wire,&slice,&integer)) return NO;
        if (field==1) { if (wire!=0 || integer>3) return NO; *type=(unsigned)integer; }
        else if (field==2) { if (wire!=2 || !(*value=MLGText(&slice,1024))) return NO; }
        else if (field==3) {
            if (wire!=2 || attrs.count>=64) return NO; NSString *key=nil;
            while (slice.cursor<slice.length) {
                unsigned af,aw; uint64_t av; MLGProto entry;
                if (!MLGField(&slice,&af,&aw,&entry,&av)) return NO;
                if (af==1) { if (aw!=2 || !(key=MLGText(&entry,256))) return NO; }
                else if ((af==2 || af==3) && aw!=0) return NO;
            }
            if (!key) return NO; [attrs addObject:key.lowercaseString];
        }
    }
    *attributes=[attrs copy]; return *value!=nil;
}
NSDictionary *MLGeoDecodeDat(NSData *data, NSString *kind, NSSet *requested, NSError **error) {
    if (error) *error=nil;
    if (!data.length || data.length>MLGeoLimit || ![@[@"geoip",@"geosite"] containsObject:kind]) return MLGFail(error,@"E_GEO_FORMAT",@"The Geo database kind or bounded protobuf input is invalid.");
    NSUInteger budget=0, total=0; MLGProto root={data.bytes,data.length,0,&budget}; NSMutableDictionary *sets=[NSMutableDictionary dictionary]; NSMutableSet *seen=[NSMutableSet set];
    while (root.cursor<root.length) {
        unsigned field,wire; uint64_t integer; MLGProto message;
        if (!MLGField(&root,&field,&wire,&message,&integer)) goto corrupt;
        if (field!=1) continue;
        if (wire!=2) goto corrupt;
        MLGProto scan=message; NSString *name=nil;
        while (scan.cursor<scan.length) {
            MLGProto part; unsigned sf,sw; uint64_t sv;
            if (!MLGField(&scan,&sf,&sw,&part,&sv)) goto corrupt;
            if (sf==1) { if (sw!=2 || !(name=MLGText(&part,256))) goto corrupt; name=name.lowercaseString; }
        }
        if (!name || [seen containsObject:name]) goto corrupt; [seen addObject:name];
        NSMutableDictionary *payloads=[NSMutableDictionary dictionary]; NSMutableDictionary *counts=[NSMutableDictionary dictionary];
        for (NSString *original in requested) {
            NSString *key=MLGeoNormalizedKey(kind,original), *base=MLGBase(key); NSString *category=[kind isEqual:@"geosite"] ? [[base componentsSeparatedByString:@"@"] firstObject] : base;
            if ([category isEqual:name]) { payloads[key]=[NSMutableData data]; counts[key]=@0; }
        }
        if (!payloads.count) continue;
        while (message.cursor<message.length) {
            MLGProto entry; unsigned ef,ew; uint64_t ev;
            if (!MLGField(&message,&ef,&ew,&entry,&ev)) goto corrupt;
            if (ef!=2) continue;
            if (ew!=2) goto corrupt;
            if ([kind isEqual:@"geoip"]) {
                const unsigned char *ip=NULL; size_t length=0; unsigned prefix=0;
                while (entry.cursor<entry.length) {
                    MLGProto bytes; unsigned cf,cw; uint64_t cv;
                    if (!MLGField(&entry,&cf,&cw,&bytes,&cv)) goto corrupt;
                    if (cf==1) { if (cw!=2 || (bytes.length!=4 && bytes.length!=16)) goto corrupt; ip=bytes.bytes; length=bytes.length; }
                    else if (cf==2) { if (cw!=0 || cv>128) goto corrupt; prefix=(unsigned)cv; }
                }
                if (!ip || prefix>length*8) goto corrupt;
                for (NSString *key in payloads) { if (!MLGAppendRange(payloads[key],length==4 ? 4 : 6,ip,prefix) || total>MLGeoLimit-33) goto resource; total+=33; }
            } else {
                unsigned type; NSString *value=nil; NSSet *attributes=nil;
                if (!MLGDomain(entry,&type,&value,&attributes)) goto corrupt;
                if (type==1 && ![NSRegularExpression regularExpressionWithPattern:value options:0 error:NULL]) return MLGFail(error,@"E_GEO_REGEX",@"A selected GeoSite regex is unavailable in the legacy engine.");
                if (type>=2) value=value.lowercaseString;
                NSData *text=[value dataUsingEncoding:NSUTF8StringEncoding]; unsigned char header[3]={(unsigned char)type,(unsigned char)(text.length>>8),(unsigned char)text.length};
                for (NSString *key in payloads) {
                    NSArray *parts=[MLGBase(key) componentsSeparatedByString:@"@"]; BOOL included=YES;
                    for (NSUInteger i=1;i<parts.count;++i) { NSString *attribute=[parts[i] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]]; if (attribute.length && ![attributes containsObject:attribute]) included=NO; }
                    if (!included) continue;
                    if (total>MLGeoLimit-text.length-3) goto resource;
                    [payloads[key] appendBytes:header length:3]; [payloads[key] appendData:text]; counts[key]=@([counts[key] unsignedIntegerValue]+1); total+=text.length+3;
                }
            }
        }
        for (NSString *key in payloads) {
            NSData *payload=[kind isEqual:@"geoip"] ? MLGMergeRanges(payloads[key]) : [payloads[key] copy];
            NSUInteger count=[kind isEqual:@"geoip"] ? payload.length/33 : [counts[key] unsignedIntegerValue];
            sets[[kind stringByAppendingFormat:@":%@",key]]=MLGSet(kind,key,payload,count,[key hasPrefix:@"!"]);
        }
    }
    for (NSString *original in requested) if (!sets[[kind stringByAppendingFormat:@":%@",MLGeoNormalizedKey(kind,original)]]) return MLGFail(error,@"E_GEO_NOT_FOUND",@"A referenced category is absent from the validated Geo database.");
    return [sets copy];
corrupt: return MLGFail(error,budget>4000000 ? @"E_GEO_RESOURCE" : @"E_GEO_PROTOBUF",budget>4000000 ? @"The selected Geo protobuf exceeds its decoding work budget." : @"The selected Geo protobuf data is malformed.");
resource: return MLGFail(error,@"E_GEO_RESOURCE",@"Referenced Geo data exceeds its 32 MiB index budget.");
}
static NSArray *MLGMMDBCodes(MMDB_entry_s *entry, NSString *databaseType, BOOL asn, BOOL *valid) {
    MMDB_entry_data_s value={0}; int code;
    if (asn) {
        BOOL numeric=[@[@"GeoLite2-ASN",@"DBIP-ASN-Lite (compat=GeoLite2-ASN)"] containsObject:databaseType];
        code=numeric ? MMDB_get_value(entry,&value,"autonomous_system_number",NULL) : MMDB_get_value(entry,&value,"asn",NULL);
        if (code==MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR || !value.has_data) return @[];
        if (code!=MMDB_SUCCESS) { *valid=NO; return nil; }
        if (numeric && value.type==MMDB_DATA_TYPE_UINT32) return @[[NSString stringWithFormat:@"%u",value.uint32]];
        if (!numeric && value.type==MMDB_DATA_TYPE_UTF8_STRING && value.data_size>2 && value.data_size<=32) {
            NSString *text=[[NSString alloc] initWithBytes:value.utf8_string length:value.data_size encoding:NSUTF8StringEncoding];
            if ([text hasPrefix:@"AS"]) return @[[text substringFromIndex:2]];
        }
        *valid=NO; return nil;
    }
    BOOL scalar=[@[@"sing-geoip",@"Meta-geoip0"] containsObject:databaseType];
    code=scalar ? MMDB_get_value(entry,&value,NULL) : MMDB_get_value(entry,&value,"country","iso_code",NULL);
    if (code==MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR || !value.has_data) return @[];
    if (code!=MMDB_SUCCESS) { *valid=NO; return nil; }
    if (value.type==MMDB_DATA_TYPE_UTF8_STRING && value.data_size<=256) {
        NSString *text=[[NSString alloc] initWithBytes:value.utf8_string length:value.data_size encoding:NSUTF8StringEncoding];
        if (!text) { *valid=NO; return nil; } return text.length ? @[text.lowercaseString] : @[];
    }
    if ([databaseType isEqual:@"Meta-geoip0"] && value.type==MMDB_DATA_TYPE_ARRAY) {
        MMDB_entry_data_list_s *list=NULL;
        if (MMDB_get_entry_data_list(entry,&list)!=MMDB_SUCCESS || !list) { *valid=NO; return nil; }
        NSMutableArray *codes=[NSMutableArray array];
        for (MMDB_entry_data_list_s *item=list->next;item;item=item->next) {
            if (codes.count>=256 || item->entry_data.type!=MMDB_DATA_TYPE_UTF8_STRING || item->entry_data.data_size>256) { *valid=NO; break; }
            NSString *text=[[NSString alloc] initWithBytes:item->entry_data.utf8_string length:item->entry_data.data_size encoding:NSUTF8StringEncoding];
            if (!text) { *valid=NO; break; } if (text.length) [codes addObject:text.lowercaseString];
        }
        MMDB_free_entry_data_list(list); return *valid ? [codes copy] : nil;
    }
    *valid=NO; return nil;
}
typedef struct { uint32_t node; unsigned depth; unsigned char address[16]; } MLGMMDBFrame;
NSDictionary *MLGeoDecodeMMDB(NSString *path, NSString *kind, NSSet *requested, NSError **error) {
    if (error) *error=nil;
    BOOL asn=[kind isEqual:@"asn"]; MMDB_s database;
    if ((!asn && ![kind isEqual:@"geoip"]) || MMDB_open(path.fileSystemRepresentation,MMDB_MODE_MMAP,&database)!=MMDB_SUCCESS) return MLGFail(error,@"E_GEO_MMDB",@"Cannot open the validated MaxMind database.");
    NSDictionary *result=nil; NSMutableDictionary *payloads=nil, *sets=nil, *matchesByOffset=nil;
    NSString *failure=@"E_GEO_MMDB"; NSString *type=database.metadata.database_type ? [NSString stringWithUTF8String:database.metadata.database_type] : @"";
    if (database.file_size<=0 || database.file_size>(ssize_t)MLGeoLimit || !database.metadata.node_count || database.metadata.node_count>4000000 || (database.metadata.ip_version!=4 && database.metadata.ip_version!=6)) goto done;
    if (asn && ![@[@"GeoLite2-ASN",@"DBIP-ASN-Lite (compat=GeoLite2-ASN)",@"ipinfo generic_asn_free.mmdb"] containsObject:type]) { failure=@"E_GEO_DB_TYPE"; goto done; }
    payloads=[NSMutableDictionary dictionary];
    for (NSString *original in requested) payloads[MLGeoNormalizedKey(kind,original)]=[NSMutableData data];
    matchesByOffset=[NSMutableDictionary dictionary];
    MLGMMDBFrame stack[129]={0}; NSUInteger length=1, operations=0,total=0; unsigned bits=database.metadata.ip_version==4 ? 32 : 128;
    while (length) { @autoreleasepool {
        MLGMMDBFrame frame=stack[--length]; MMDB_search_node_s node;
        if (++operations>8000000 || frame.depth>=bits || MMDB_read_node(&database,frame.node,&node)!=MMDB_SUCCESS) goto done;
        for (unsigned side=0;side<2;++side) {
            unsigned char address[16]; memcpy(address,frame.address,16); if (side) address[frame.depth/8]|=(unsigned char)(1u<<(7-frame.depth%8)); unsigned depth=frame.depth+1;
            uint8_t recordType=side ? node.right_record_type : node.left_record_type; uint64_t record=side ? node.right_record : node.left_record;
            if (recordType==MMDB_RECORD_TYPE_EMPTY) continue;
            if (recordType==MMDB_RECORD_TYPE_SEARCH_NODE) {
                if (length>=129 || record>=database.metadata.node_count || depth>=bits) goto done;
                stack[length].node=(uint32_t)record; stack[length].depth=depth; memcpy(stack[length].address,address,16); ++length;
            } else if (recordType==MMDB_RECORD_TYPE_DATA) {
                MMDB_entry_s entry=side ? node.right_record_entry : node.left_record_entry; BOOL valid=YES;
                NSNumber *offset=@(entry.offset);
                NSArray *codes=matchesByOffset[offset];
                if (!codes) {
                    NSArray *decoded=MLGMMDBCodes(&entry,type,asn,&valid); if (!valid) goto done;
                    NSMutableArray *matched=[NSMutableArray array];
                    for (NSString *key in decoded) if (payloads[key]) [matched addObject:key];
                    codes=matched.count ? [matched copy] : @[];
                    if (matchesByOffset.count>=4096) [matchesByOffset removeAllObjects];
                    matchesByOffset[offset]=codes;
                }
                for (NSString *key in codes) {
                    if (!MLGAppendRange(payloads[key],bits==32 ? 4 : 6,address,depth) || total>MLGeoLimit-33) { failure=@"E_GEO_RESOURCE"; goto done; } total+=33;
                    static const unsigned char zero[12]={0};
                    if (bits==128 && depth>=96 && !memcmp(address,zero,12)) {
                        if (!MLGAppendRange(payloads[key],4,address+12,depth-96) || total>MLGeoLimit-33) { failure=@"E_GEO_RESOURCE"; goto done; } total+=33;
                    }
                }
            } else goto done;
        }
    }}
    sets=[NSMutableDictionary dictionary];
    for (NSString *key in payloads) { NSData *payload=MLGMergeRanges(payloads[key]); sets[[kind stringByAppendingFormat:@":%@",key]]=MLGSet(kind,key,payload,payload.length/33,NO); }
    result=[sets copy];
done:
    MMDB_close(&database); return result ?: MLGFail(error,failure,@"The referenced MaxMind data is malformed, unsupported or exceeds the 32 MiB resource budget.");
}
static void MLGUInt(NSMutableData *data, uint32_t value, unsigned bytes) {
    unsigned char buffer[4]; for (unsigned i=0;i<bytes;++i) buffer[i]=(unsigned char)(value>>(8*(bytes-i-1))); [data appendBytes:buffer length:bytes];
}
NSData *MLGeoEncodeIndex(NSDictionary *sets, NSError **error) {
    if (sets.count>256) return MLGFail(error,@"E_GEO_RESOURCE",@"At most 256 Geo categories may be referenced in one generation.");
    NSMutableData *output=[NSMutableData dataWithBytes:"MLGEO1\0\0" length:8]; MLGUInt(output,(uint32_t)sets.count,4);
    for (NSString *name in [sets.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
        NSDictionary *set=sets[name]; NSString *kind=set[@"kind"]; NSData *key=[set[@"key"] dataUsingEncoding:NSUTF8StringEncoding], *payload=set[@"payload"];
        if (!key.length || key.length>256 || payload.length>MLGeoLimit || key.length+12>MLGeoLimit-payload.length || output.length>MLGeoLimit-key.length-payload.length-12) return MLGFail(error,@"E_GEO_RESOURCE",@"The compact referenced Geo index exceeds 32 MiB.");
        unsigned char header[2]={[kind isEqual:@"geoip"] ? 0 : ([kind isEqual:@"asn"] ? 1 : 2),[set[@"inverse"] boolValue] ? 1 : 0};
        [output appendBytes:header length:2]; MLGUInt(output,(uint32_t)key.length,2); MLGUInt(output,(uint32_t)[set[@"count"] unsignedIntegerValue],4); MLGUInt(output,(uint32_t)payload.length,4); [output appendData:key]; [output appendData:payload];
    }
    return [output copy];
}
