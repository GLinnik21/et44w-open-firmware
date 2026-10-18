/* Symbols the Realtek SDK core expects from example code we don't build (Wi-Fi fast connect,
 * Bluetooth, Realtek OTA). Wi-Fi credentials and OTA are handled by our own code instead. */
#include <stdint.h>
#include <stddef.h>

typedef int (*write_reconnect_ptr)(uint8_t *data, uint32_t len);

/* wlan_fast_connect example: wifi_conf.c skips saving when this is NULL. */
write_reconnect_ptr p_write_reconnect_ptr = NULL;
/* lwip_netconf.c: DHCP fast-reconnect hints, 0 = do a normal DHCP discover. */
uint32_t offer_ip = 0;
uint32_t server_ip = 0;

int Erase_Fastconnect_data(void) { return 0; }

/* wifi_conf.c reads the current mode; the AT console (atcmd_wifi.c, not built) normally owns it. */
int wifi_mode = 1; /* rtw_mode_t RTW_MODE_STA (wifi_constants.h); this lib doesn't see the SDK headers */

/* ATWO (Realtek OTA over the AT console) is not supported. */
void cmd_update(int argc, char **argv) { (void)argc; (void)argv; }
