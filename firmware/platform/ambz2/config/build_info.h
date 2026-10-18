/* The SDK normally generates this per build; only its AT-console version banner used it, and no source we
 * build includes it now. Fixed strings, no __DATE__, so it can't make builds differ. (The one date stamp left
 * in a HAP image is the ADK build string, HAPPlatformGetBuild in libs/hap-pal-ambz2.) */
#define RTL_FW_COMPILE_TIME      RTL8710CFW_COMPILE_TIME
#define RTL_FW_COMPILE_DATE      RTL8710CFW_COMPILE_DATE
#define UTS_VERSION              "homekit-ambz2"
#define RTL8710CFW_COMPILE_TIME  "-"
#define RTL8710CFW_COMPILE_DATE  "-"
#define RTL8710CFW_COMPILE_BY    "build"
#define RTL8710CFW_COMPILE_HOST  "host"
#define RTL8710CFW_COMPILE_DOMAIN
#define RTL8710CFW_COMPILER      "gcc " __VERSION__
