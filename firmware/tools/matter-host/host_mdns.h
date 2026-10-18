/* mDNS for matter-host through macOS mDNSResponder: one `dns-sd -R` child per record of the node's record set
 * (mt_node_mdns_get). A record that changes is withdrawn (child killed) and registered again. */
#ifndef MH_MDNS_H
#define MH_MDNS_H

#include "mt_node.h"

/* log_dir: each child's output goes to <log_dir>/mdns-<slot>.log (NULL = /dev/null). */
void mh_mdns_init(uint16_t port, const char *log_dir);
/* Re-read the node's records and bring the children in line. */
void mh_mdns_sync(const mt_node *n);
/* Kill every child (call on exit). */
void mh_mdns_stop(void);

#endif
