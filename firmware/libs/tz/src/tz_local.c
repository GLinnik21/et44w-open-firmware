#include "tz.h"
#include "tz_priv.h"

/* Local-wall-clock seconds since 1970 at which rule r fires in `year`. */
static int64_t RuleLocal(const tz_rule *r, int32_t year)
{
    int64_t first = tz_days_from_civil(year, r->month, 1);
    int64_t wday1 = (first + 4) % 7; /* 1970-01-01 was a Thursday (POSIX wday 4) */
    int64_t day = first + (r->wday - wday1 + 7) % 7 + (int64_t)(r->week - 1) * 7;
    if (r->week == 5) {
        uint32_t nm = r->month == 12 ? 1 : r->month + 1u;
        int64_t next = tz_days_from_civil(r->month == 12 ? year + 1 : year, nm, 1);
        while (day >= next) day -= 7;
    }
    return day * 86400 + r->time;
}

static bool InDst(const tz_zone *z, int64_t utc)
{
    tz_civil c;
    tz_civil_from_epoch(utc + z->std_offset, &c);
    int64_t start = RuleLocal(&z->start, c.year) - z->std_offset; /* start is in standard time */
    int64_t end = RuleLocal(&z->end, c.year) - z->dst_offset;     /* end is in DST */
    return start < end ? utc >= start && utc < end : utc >= start || utc < end; /* southern zones */
}

void tz_local(const tz_zone *z, int64_t utc, tz_civil *out)
{
    int32_t off = z->has_dst && InDst(z, utc) ? z->dst_offset : z->std_offset;
    tz_civil_from_epoch(utc + off, out);
}
