# Configuration checking and storage

`config/MLConfig` parses a single Clash-style YAML mapping with pinned libyaml 0.2.5. The event reader rejects aliases, anchors, explicit tags/tag directives, complex or non-string mapping keys, duplicate keys and additional documents. Input is limited to 512 KiB of UTF-8, nesting to 32 levels and nodes to 20,000. Mapping keys are limited to 256 UTF-8 bytes and diagnostic paths to 1024 bytes, preventing path memory amplification. The issue report is limited to 256 entries. A parsing failure marks remaining checks as unchecked; a partial document is never presented as a valid configuration.

`+checkYAML:` returns an immutable dictionary with `valid`, `syntaxValid`, `document`, `issues` and `unchecked`. Issues contain `id`, `category`, `severity`, `field`, `line`, `column`, `reason`, `impact` and `suggestion`. Locations are one-based libyaml locations. Missing fields point to the nearest existing parent. Byte-limit failures have no source location and use zero. Unknown keys are blockers. Known sections without an implementation are also blockers and explicitly mark their nested fields unchecked. Every original field remains in the parsed document; nothing is translated into an executable command.

The public `config.check` IPC response excludes `document`, so reports and before/after diagnostic comparisons do not include raw credentials or an unnecessary second configuration copy. Raw YAML is available only via the explicit source endpoint.

The scalar schema recognizes quoted strings, plain `true`/`false`, nulls, bounded decimal integers and finite decimal numbers. Other plain scalar values remain strings. There is no YAML object construction or implicit filesystem/network access. Unquoted numeric or boolean mapping keys are rejected; quote such keys when a string key is intended.

Semantic checks cover proxy and group names, required protocol fields, port ranges, UUIDs, boolean flags, transport options, group references, cycles and depth, rule target references, CIDR prefixes, network values, port expressions, and domain regex syntax. Unsupported fields and options are reported at their source locations.

`valid` means that this checker found no hard blockers. A runtime-unverified issue is always present. Activation requires a successful preparation acknowledgement. Connection and capture status come from the running service.

## TCP routing and selectors

The routing layer compiles the rules for each immutable configuration and evaluates them in configuration order. The first match selects a named outbound, selector, or the `DIRECT`/`REJECT` builtins. Rule mode uses `DIRECT` when no rule matches. Direct mode always selects `DIRECT`. Global mode uses the `GLOBAL` selector. If the configuration omits that group, its members are `DIRECT`, `REJECT`, the named outbounds, and the configured groups, in that order. An explicit `GLOBAL` uses its configured members. [Pinned Mihomo tunnel](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/tunnel/tunnel.go), [pinned Mihomo config](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/config/config.go)

Selectors take an ordered `proxies` list or obtain members from Provider `use`/include-all options. A selector uses the current selection, its configured `default-selected` member, or its first member, in that order. It exposes the immediate selection and the resolved outbound separately. Automatic groups support url-test, fallback, and load-balance with round-robin, consistent-hashing or sticky-sessions. Relay groups and dialer-proxy references resolve an ordered chain of at most sixteen actual proxy stages. Group and proxy health show as unknown until measured.

Supported rules include `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `DOMAIN-REGEX`, `IP-CIDR`, `IP-CIDR6`, `SRC-IP-CIDR`, `SRC-PORT`, `DST-PORT`, `NETWORK,TCP`, and `MATCH`. Both destination CIDR spellings accept IPv4 and IPv6. A destination CIDR rule can request one lazy DNS lookup. A rule with `no-resolve` uses a supplied IP literal or the result of an earlier lookup. The `src` option switches a destination CIDR rule to the source address. Domain regexes use Foundation's case-insensitive regex engine, whose syntax can differ from Mihomo's. [Pinned Mihomo rule parser](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/rules/parser.go), [pinned Mihomo domain regex](https://github.com/MetaCubeX/mihomo/blob/0455d0d28c4526937380505153e65a843d8612e8/rules/common/domain_regex.go)

AND/OR/NOT, RULE-SET and SUB-RULE are implemented, with bounded recursion and inherited no-resolve. PROCESS-NAME/PATH match only reliable process metadata. GEOIP/GEOSITE/IP-ASN require preparation against validated protobuf/MMDB data and an immutable Core index; missing referenced categories prevent activation. Provider sources support verified HTTPS, private files and inline payloads, plus YAML/text and bounded domain/ipcidr MRSv1 decoding. [Policies, Provider and Geo behavior](POLICIES-PROVIDERS.md) documents algorithms, transactions, resource limits and explicit unsupported extensions. Additional builtin actions and unsupported protocol combinations remain blockers.

Provider paths accept one conventional leading `./`, such as `./ruleset/direct.yaml`. File imports and reads strip that prefix and construct the path under the private Provider `local/` root. The original configuration text remains intact. Absolute paths, empty components, further `.`/`..` components, and symbolic links are rejected. HTTP Provider `path` values use the same relative-path checks; downloaded snapshots remain in the managed content-hash cache.

## Proxy share import

The node import action accepts a single share URI, newline-separated URI entries, or a UTF-8 list wrapped in standard or URL-safe Base64. The input limit is 256 KiB, with up to 128 nodes and 8 KiB per URI. Supported schemes are `socks5://`, `http://`, `https://`, `trojan://`, and `vless://`. Credentials and display names support percent encoding. Put IPv6 server literals in brackets.

HTTP, HTTPS and SOCKS5 accept an optional username/password pair in the URI and default to ports 80, 443 and 1080. Trojan and VLESS require explicit ports. Trojan uses verified TLS. VLESS supports raw TCP with optional verified TLS and `encryption=none`. Unsupported schemes, transports, options, and malformed values reject the entire list. [Trojan URI format](https://github.com/trojan-gfw/trojan-url/blob/master/README.md), [Xray sharing proposal](https://github.com/XTLS/Xray-core/discussions/716)

An import creates a candidate with a `PROXY` selector that contains the imported nodes in order and a `MATCH,PROXY` rule. Duplicate or reserved display names get numeric suffixes. Activation uses the same preparation and validation as other candidates.

## Immutable candidate store

`MLConfigStore` accepts a fixed, absolute, application-owned path. All path components must be directories without symlinks; use the canonical `/private/var/...` path on the device. The final directory belongs to the service user and is mode 0700. The root supervisor owns production storage; UI access goes through permission-checked IPC.

Each import creates a new CFUUID identifier and immutable JSON record containing YAML, name, source and timestamp. Files and the cross-process lock are mode 0600. Record reads reject symlinks, hard links, foreign ownership, incorrect permissions, oversized files and truncated/changing reads. Identifiers are UUID-shaped strings, never paths. List metadata includes `id`, `name`, `source`, `nodeCount`, `updatedAt`, `status` and `active`; timestamps are Unix seconds. Unreadable records appear with an explicit unreadable status.

Candidates with syntactically valid YAML can be stored even when semantic or compatibility checks fail, so they can be inspected and edited. Malformed YAML is refused. Applying a candidate rechecks it, refuses blockers, and calls `prepare(document,error)` with the immutable parsed document. A missing or failed callback leaves the current active ID unchanged. Only a successful callback permits an atomic replacement of the active-ID marker. Activation does not itself start networking. Existing records are never overwritten by imports; failed subscription updates can therefore preserve the previous candidate and active generation.

Writes use an exclusively created temporary file, complete write loop, file fsync, atomic rename and directory fsync under a store lock. Rename is the commit point. If the final directory fsync fails after rename, the operation is already committed and reports success; a log records uncertain power-loss durability without logging configuration contents. Failures before commit leave the previous record/marker intact. The active record cannot be removed. Removing a stopped active configuration requires the service to select another configuration first.

## Verification and remaining scope

`tests/config.m` exercises bounded YAML parsing, diagnostic locations, semantic checks, runtime capability blockers, candidate persistence, failed-prepare preservation, private permissions and symlink/path rejection. The tests use libyaml and temporary files. `tests/routing.m` exercises first-match ordering, case-insensitive domains, CIDR boundaries, DNS timing, ports, and nested selection in each routing mode. `tests/node_import.m` checks URI and Base64 conversion, generated routing and input limits.

The build compiles these sources for `armv7-apple-ios6.0` against SDK 7.1 with API availability warnings promoted to errors. Target-device acceptance still requires a physical device.
