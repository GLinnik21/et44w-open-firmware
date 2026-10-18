// Local web page with every thermostat setting: http://<ip>/ or http://<mdns host>.local/. The MCU link must
// call dp_cache_put() for every DP report.
//   GET  /           the page (web/index.html, embedded at build time)
//   GET  /api/state  JSON: all reported DPs, the weekly schedule records, firmware and heap
//   POST /api/dp     form "dp=<id>&v=<value>": one DP write, checked against libs/thermo thermo_dp.c
// No login (by design: LAN only); httpd refuses foreign Host names and POSTs without X-Requested-With.
#ifndef WEB_H
#define WEB_H

#define WEB_PORT 80

// name and fw go into /api/state (the page title and footer). Both must stay valid (string literals).
void web_start(const char* name, const char* fw);

#endif
