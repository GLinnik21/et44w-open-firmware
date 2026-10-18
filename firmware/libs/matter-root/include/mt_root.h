/* Matter endpoint-0 clusters. Each cluster is one source file and a handler for matter-dm (mt_dm_cluster).
 * Pure C11, no allocation. The cluster objects are caller-owned and must outlive the mt_dm they are listed in.
 *
 * Basic Information (spec 1.3 section 11.1, cluster revision 3, checked against the 1.3.0.0 cluster IDL):
 *   fixed attributes 0-4, 7-10, 15, 18, 19, 21, 22 from the config; NodeLabel (5, write: Manage) and
 *   Location (6, write: Administer) are writable and persisted through the kv port as one TLV record.
 *   Not implemented (all optional): ManufacturingDate, PartNumber, ProductURL, ProductLabel,
 *   LocalConfigDisabled, Reachable, ProductAppearance. Event 0 (StartUp) is declared; the node emits it. */
#ifndef MT_ROOT_H
#define MT_ROOT_H

#include "mt_dm.h"
#include "mt_core.h" /* mt_kv_ops */

#define MT_BASIC_CLUSTER_ID 0x0028u
#define MT_BASIC_EVENT_STARTUP 0u

enum { /* attribute ids */
    MT_BASIC_DATA_MODEL_REVISION = 0, MT_BASIC_VENDOR_NAME = 1, MT_BASIC_VENDOR_ID = 2,
    MT_BASIC_PRODUCT_NAME = 3, MT_BASIC_PRODUCT_ID = 4, MT_BASIC_NODE_LABEL = 5, MT_BASIC_LOCATION = 6,
    MT_BASIC_HARDWARE_VERSION = 7, MT_BASIC_HARDWARE_VERSION_STRING = 8, MT_BASIC_SOFTWARE_VERSION = 9,
    MT_BASIC_SOFTWARE_VERSION_STRING = 10, MT_BASIC_SERIAL_NUMBER = 15, MT_BASIC_UNIQUE_ID = 18,
    MT_BASIC_CAPABILITY_MINIMA = 19, MT_BASIC_SPECIFICATION_VERSION = 21, MT_BASIC_MAX_PATHS_PER_INVOKE = 22
};

#define MT_BASIC_DATA_MODEL_REV 17u        /* Matter 1.3 */
#define MT_BASIC_SPEC_VERSION 0x01030000u  /* 1.3.0.0 */
#define MT_BASIC_LABEL_MAX 32
#define MT_BASIC_LOCATION_LEN 2

/* Strings are NUL-terminated and must outlive the cluster (typically string literals). */
typedef struct {
    const char *vendor_name;           /* <= 32 */
    uint16_t vendor_id;
    const char *product_name;          /* <= 32 */
    uint16_t product_id;
    uint16_t hardware_version;
    const char *hardware_version_str;  /* <= 64 */
    uint32_t software_version;
    const char *software_version_str;  /* <= 64 */
    const char *serial_number;         /* <= 32 */
    const char *unique_id;             /* <= 32 */
    uint16_t case_sessions_per_fabric; /* CapabilityMinima, >= 3 */
    uint16_t subscriptions_per_fabric; /* >= 3 */
    uint16_t max_paths_per_invoke;     /* what the IM engine supports */
} mt_basic_cfg;

typedef struct {
    const mt_basic_cfg *cfg;
    const mt_kv_ops *kv;               /* NULL: NodeLabel and Location are not persisted */
    uint16_t kv_key;                   /* record for label and location, e.g. MT_FKEY(0, n) */
    char label[MT_BASIC_LABEL_MAX + 1];
    char location[MT_BASIC_LOCATION_LEN + 1];
    mt_dm_cluster cluster;             /* list &b->cluster in the endpoint-0 cluster table */
} mt_basic;

/* Fills b and loads label/location from kv_key (defaults: empty label, "XX"; an absent or corrupt record
 * leaves the defaults). cfg must outlive b. MT_ERR_INVALID if cfg lacks a string. */
mt_err mt_basic_init(mt_basic *b, const mt_basic_cfg *cfg, const mt_kv_ops *kv, uint16_t kv_key);

/* Set Location (SetRegulatoryConfig's CountryCode, spec 11.10.7.4) and persist it; RAM keeps the old value on a
 * storage error. MT_ERR_INVALID unless len == 2. The caller reports the change (mt_dm_changed). */
mt_err mt_basic_set_location(mt_basic *b, const char *cc, size_t len);

/* The StartUp event's fields: {0: SoftwareVersion}. Returns the encoded length. */
size_t mt_basic_startup_fields(const mt_basic *b, uint8_t *out, size_t cap);

#endif
