/* TuyaMCU command bytes and codes. */
#ifndef TM_CMD_H
#define TM_CMD_H

enum {
    TM_CMD_HEARTBEAT = 0x00,
    TM_CMD_PRODUCT = 0x01,
    TM_CMD_MODE = 0x02,
    TM_CMD_NET_REPORT = 0x03, /* module -> MCU network status; the MCU acks with an empty 0x03 */
    TM_CMD_WIFI_RESET = 0x04,
    TM_CMD_WIFI_MODE = 0x05, /* reset + select SmartConfig(0)/AP(1) */
    TM_CMD_DP_SEND = 0x06,   /* module -> MCU */
    TM_CMD_DP_REPORT = 0x07, /* MCU -> module */
    TM_CMD_QUERY = 0x08,
    TM_CMD_OTA_START = 0x0A, /* never used */
    TM_CMD_OTA_DATA = 0x0B,  /* never used */
    TM_CMD_TIME_GMT = 0x0C,
    TM_CMD_TIME_LOCAL = 0x1C,
    TM_CMD_NET_QUERY = 0x2B,  /* MCU asks for the network status; answered with 0x2B */
    TM_CMD_TEST = 0xF0        /* production test, ignored */
};

/* Network status sent to the MCU. */
enum {
    TM_NET_PAIRING = 0x00,  /* waiting for setup (Tuya: EZ/smartconfig, the icon blinks fast) */
    TM_NET_SOFTAP = 0x01,
    TM_NET_NO_LINK = 0x02,  /* credentials stored, not connected */
    TM_NET_UNPAIRED = 0x03, /* on Wi-Fi, not paired to a controller */
    TM_NET_PAIRED = 0x04    /* on Wi-Fi, paired to a controller */
};

#endif
