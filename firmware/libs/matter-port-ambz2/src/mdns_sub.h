/* DNS-SD subtype PTR records for the Matter node (pure packet code, no lwIP; host tests in test/).
 *
 * lwIP 2.0.2's responder has no subtypes, so this answers them next to it. A subtype is a PTR record
 * `<sub>._sub.<service>.<proto>.local  PTR  <instance>.<service>.<proto>.local` (RFC 6763 section 7.1), e.g.
 * `_S15._sub._matterc._udp.local`; Matter 1.3 spec 4.3.1 (_L<disc>, _S<short>, _V<vid>, _CM) and 4.3.2 (_I<CFID>).
 * Only PTR / ANY questions for those names are answered; SRV, TXT, A and AAAA stay with lwIP (a resolver asks for
 * them next). */
#ifndef MTP_MDNS_SUB_H
#define MTP_MDNS_SUB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MTP_MSUB_TTL_S 120      /* as the other records */
#define MTP_MSUB_MAX 32         /* entries one call handles */

typedef struct {
    const char *sub;            /* "_S15", "_I<CFID>": without "._sub" */
    const char *instance;       /* instance label of the service the subtype points at */
    bool operational;           /* _matter._tcp, else _matterc._udp */
} mtp_msub_ent;

/* Answer the questions of the mDNS packet `in` that name one of the `cnt` subtypes. `legacy` = the query came
 * from a port other than 5353 (RFC 6762 section 6.7: the reply echoes id and question, short TTL, unicast).
 * Known-answer suppression (section 7.1) is honoured. Writes a response to `out` and returns its length; 0 =
 * nothing to send. *unicast: send to the querier instead of the multicast group (legacy or QU bit). */
size_t mtp_msub_reply(const uint8_t *in, size_t n, bool legacy, const mtp_msub_ent *tab, unsigned cnt,
                      uint8_t *out, size_t cap, bool *unicast);

/* Unsolicited multicast response carrying every subtype PTR (the part of an announcement lwIP can't send). */
size_t mtp_msub_announce(const mtp_msub_ent *tab, unsigned cnt, uint8_t *out, size_t cap);

/* Goodbye (RFC 6762 section 10.1): the same PTR records with TTL 0, for services that went away (lwIP 2.0.2
 * sends none, so a closed commissioning window lingered in caches). An entry with sub == NULL stands for the
 * service's own PTR `<service>.<proto>.local PTR <instance>...`; mtp_msub_reply never gets such entries. */
size_t mtp_msub_goodbye(const mtp_msub_ent *tab, unsigned cnt, uint8_t *out, size_t cap);

#endif
