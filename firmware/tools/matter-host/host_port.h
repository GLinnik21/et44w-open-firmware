/* POSIX ports for matter-node on the Mac/Linux: dual-stack UDP, file-backed kv, /dev/urandom, monotonic clock. */
#ifndef MH_PORT_H
#define MH_PORT_H

#include "mt_node.h"

uint32_t mh_now_ms(void);
int mh_entropy(void *ctx, uint8_t *out, size_t len);   /* mt_entropy_fn over /dev/urandom */

/* Dual-stack UDP socket on [::]:port (0 = pick one); falls back to IPv4 only if IPv6 is missing.
 * Returns the fd or -1; *bound_port is the port actually bound. */
int mh_udp_open(uint16_t port, uint16_t *bound_port);
void mh_udp_send(int fd, const mt_node_addr *to, mt_span frame);
/* Receives one datagram (non-blocking after poll); returns its length, 0 if none, -1 on error. */
long mh_udp_recv(int fd, mt_node_addr *from, uint8_t *buf, size_t cap);

/* File-backed mt_kv_ops in dir (created if absent): all records in one file (64 KiB at most, 1 KiB a value,
 * 16 keys per commit). finish(apply) is atomic: the new image is written to a temp file, fsynced and renamed
 * over the old one, then the directory is fsynced. One store per process (static state). */
typedef struct mh_kv mh_kv;
mh_kv *mh_kv_open(const char *dir, mt_kv_ops *ops_out);
/* Test hook: when >= 0, finish(apply) stops dead (as if the process crashed) before its (n+1)-th commit step. */
extern int mh_kv_crash_after;

#endif
