/* Time Synchronization (0x38): included by test_comm.c, shares its fixture. */
#define TS MT_TIMESYNC_CLUSTER_ID

static mt_im_status set_utc(int sid, bool has_utc, uint64_t us, int gran, int src)
{
    mt_tlv_wr *w = req();
    if (has_utc) mt_tlv_put_u(w, mt_tlv_ctx(0), us);
    if (gran >= 0) mt_tlv_put_u(w, mt_tlv_ctx(1), (uint64_t)gran);
    if (src >= 0) mt_tlv_put_u(w, mt_tlv_ctx(2), (uint64_t)src);
    return invoke(sid, TS, 0, w, NULL, NULL);
}
/* UTCTime attribute: true with *us when set, false when null. */
static bool read_utc(uint64_t *us)
{
    mt_tlv_rd r;
    CHECK(rd(S_PASE, false, TS, 0, 0, &r) == MT_OK);
    if (r.type == MT_TLV_NULL) return false;
    CHECK(!mt_tlv_get_u64(&r, us));
    return true;
}

static void test_timesync(void)
{
    mt_tlv_rd r;
    mt_im_attr a;
    mt_tlv_wr *w;
    uint64_t us = 0;
    uint32_t dv, dv2;
    const uint64_t T0 = 700000000ull * 1000000ull; /* Matter-epoch us, 2022: inside the test certificates' validity */
    fx_init(false);
    fx_session(S_PASE, MT_IM_AUTH_PASE, 0, 0);

    /* shape: rev 2, no features, UTCTime/Granularity/TimeSource, SetUTCTime, TimeFailure event; read-only */
    CHECK(rd_u(TS, 0xFFFD, 2) && rd_u(TS, 0xFFFC, 0));
    CHECK(list_len(S_PASE, false, TS, 0xFFFB) == 3 + 6);          /* 3 + the six global attributes (EventList is declared) */
    CHECK(list_len(S_PASE, false, TS, 0xFFF9) == 1 && rd_u(TS, 0xFFF9, 0));
    CHECK(list_len(S_PASE, false, TS, 0xFFF8) == 0);
    CHECK(list_len(S_PASE, false, TS, 0xFFFA) == 1 && rd(S_PASE, false, TS, 0xFFFA, 0, &r) == MT_OK);
    CHECK(find_attr(TS, 0, &a) && (a.flags & MT_IM_ATTR_OMITTED) && !(a.flags & MT_IM_ATTR_WRITABLE));
    CHECK(find_attr(TS, 1, &a) && !(a.flags & MT_IM_ATTR_WRITABLE) && find_attr(TS, 2, &a) && !(a.flags & MT_IM_ATTR_WRITABLE));
    CHECK(!find_attr(TS, 3, &a) && !find_attr(TS, 5, &a));       /* feature attributes are absent */
    w = req(); mt_tlv_put_u(w, mt_tlv_ctx(0), 1);
    CHECK(invoke(S_PASE, TS, 1, w, NULL, NULL) == MT_IM_UNSUPPORTED_COMMAND);
    CHECK(invoke(S_PASE, TS, 2, req(), NULL, NULL) == MT_IM_UNSUPPORTED_COMMAND);

    /* unknown after boot */
    CHECK(!read_utc(&us) && rd_u(TS, 1, MT_TIME_GRAN_NONE) && rd_u(TS, 2, MT_TIME_SRC_NONE));
    CHECK(mt_root_utc_now(&F.r) == 0 && !mt_root_utc_us(&F.r, &us));

    {   /* SetUTCTime needs Administer: PASE has it, a CASE session without an ACL entry does not (checked again
         * through the IM engine at the end) */
        uint8_t priv = 0;
        bool timed = true;
        mt_im_cmd c = { 0, TS, 0 };
        mt_im_subject sp = subj(S_PASE);
        CHECK(mt_dm_im.cmd_info(&F.dm, &c, &priv, &timed) == MT_OK && priv == MT_IM_PRIV_ADMINISTER && !timed);
        CHECK(mt_dm_im.access(&F.dm, &sp, 0, TS, MT_IM_PRIV_ADMINISTER));
    }
    /* field checks: nothing changes, the hook stays quiet */
    CHECK(set_utc(S_PASE, false, 0, MT_TIME_GRAN_US, 2) == MT_IM_INVALID_COMMAND);
    CHECK(set_utc(S_PASE, true, T0, -1, 2) == MT_IM_INVALID_COMMAND);
    w = req(); mt_tlv_put_utf8(w, mt_tlv_ctx(0), "x", 1); mt_tlv_put_u(w, mt_tlv_ctx(1), 4);
    CHECK(invoke(S_PASE, TS, 0, w, NULL, NULL) == MT_IM_INVALID_COMMAND);
    w = req(); mt_tlv_put_u(w, mt_tlv_ctx(0), T0); mt_tlv_put_utf8(w, mt_tlv_ctx(1), "x", 1);
    CHECK(invoke(S_PASE, TS, 0, w, NULL, NULL) == MT_IM_INVALID_COMMAND);
    CHECK(set_utc(S_PASE, true, T0, MT_TIME_GRAN_NONE, 2) == MT_IM_CONSTRAINT_ERROR);
    CHECK(set_utc(S_PASE, true, T0, 5, 2) == MT_IM_CONSTRAINT_ERROR);
    CHECK(set_utc(S_PASE, true, T0, MT_TIME_GRAN_US, MT_TIME_SRC_MAX + 1) == MT_IM_CONSTRAINT_ERROR);
    CHECK(!F.utc_calls && !read_utc(&us) && mt_root_utc_now(&F.r) == 0);

    /* accepted, TimeSource absent = Admin; the time runs on the node clock */
    CHECK(mt_dm_dataver(&F.dm, 0, TS, &dv));
    F.now = 5000;
    CHECK(set_utc(S_PASE, true, T0, MT_TIME_GRAN_MS, -1) == MT_IM_SUCCESS);
    CHECK(F.utc_calls == 1 && F.utc_us == T0 && F.utc_gran == MT_TIME_GRAN_MS && F.utc_src == MT_TIME_SRC_ADMIN);
    CHECK(mt_dm_dataver(&F.dm, 0, TS, &dv2) && dv2 != dv);
    CHECK(read_utc(&us) && us == T0 && rd_u(TS, 1, MT_TIME_GRAN_MS) && rd_u(TS, 2, MT_TIME_SRC_ADMIN));
    F.now += 1500;
    CHECK(read_utc(&us) && us == T0 + 1500000ull);
    CHECK(mt_root_utc_now(&F.r) == 700000001u);                  /* whole seconds */
    /* the 32-bit node clock wrapping does not disturb it */
    F.now = 0xFFFFFF00u;
    CHECK(set_utc(S_PASE, true, T0, MT_TIME_GRAN_US, MT_TIME_SRC_UNKNOWN) == MT_IM_SUCCESS && rd_u(TS, 2, MT_TIME_SRC_UNKNOWN));
    F.now = 0x100u;                                              /* 0x200 ms later */
    CHECK(read_utc(&us) && us == T0 + 512000ull);
    F.now = 0xFFFFFF00u + 0x7FFFFFF0u;                          /* a long time on: mt_root_poll folds it in */
    (void)mt_root_poll(&F.r);
    F.now += 0x7FFFFFF0u;
    CHECK(read_utc(&us) && us == T0 + 512000ull + ((uint64_t)0x7FFFFDF0u + 0x7FFFFFF0u) * 1000ull);
    /* another administrator may replace an Admin time, even with a coarser granularity */
    CHECK(set_utc(S_PASE, true, T0, MT_TIME_GRAN_MINUTES, 2) == MT_IM_SUCCESS && F.utc_calls == 3);

    /* the device's own time (SNTP): replaces unconditionally, no hook; a coarser SetUTCTime is TimeNotAccepted */
    CHECK(mt_root_set_utc(&F.r, T0 + 5000000ull, MT_TIME_GRAN_NONE, MT_TIME_SRC_NONMATTER_SNTP) == MT_ERR_INVALID);
    CHECK(mt_root_set_utc(&F.r, T0, MT_TIME_GRAN_US + 1, MT_TIME_SRC_NONMATTER_SNTP) == MT_ERR_INVALID);
    CHECK(mt_root_set_utc(&F.r, T0, MT_TIME_GRAN_MS, MT_TIME_SRC_MAX + 1) == MT_ERR_INVALID);
    CHECK(read_utc(&us) && us == T0 && rd_u(TS, 2, MT_TIME_SRC_ADMIN));   /* still the Admin time */
    CHECK(mt_dm_dataver(&F.dm, 0, TS, &dv));
    CHECK(mt_root_set_utc(&F.r, T0 + 9000000ull, MT_TIME_GRAN_MS, MT_TIME_SRC_NONMATTER_SNTP) == MT_OK);
    CHECK(F.utc_calls == 3 && mt_dm_dataver(&F.dm, 0, TS, &dv2) && dv2 != dv);
    CHECK(read_utc(&us) && us == T0 + 9000000ull && rd_u(TS, 1, MT_TIME_GRAN_MS) && rd_u(TS, 2, MT_TIME_SRC_NONMATTER_SNTP));
    CHECK(set_utc(S_PASE, true, T0, MT_TIME_GRAN_SECONDS, 2) == MT_IM_CST(MT_TIME_CST_NOT_ACCEPTED));
    CHECK(read_utc(&us) && us == T0 + 9000000ull && F.utc_calls == 3);
    CHECK(set_utc(S_PASE, true, T0 + 1000000ull, MT_TIME_GRAN_MS, 2) == MT_IM_SUCCESS && F.utc_calls == 4);

    /* certificate validity follows the clock: unknown = skipped, set = checked (AddNOC; CASE uses the same value) */
    {
        mt_tlv_rd o;
        mt_im_status st;
        for (int pass = 0; pass < 3; pass++) {
            uint64_t t = pass == 0 ? 0 : pass == 1 ? 1500000000ull * 1000000ull : T0;
            fx_init(false);
            fx_session(S_PASE, MT_IM_AUTH_PASE, 0, 0);
            CHECK(arm(S_PASE, 60, 1) == MT_COMM_OK);
            CHECK(csr(S_PASE, "Node01_02", k_Node01_02_priv, -1, &o) == MT_IM_SUCCESS);
            CHECK(add_trc(S_PASE, "Root01") == MT_IM_SUCCESS);
            if (t) CHECK(set_utc(S_PASE, true, t, MT_TIME_GRAN_US, 2) == MT_IM_SUCCESS);
            st = 0;
            int code = add_noc(S_PASE, "Node01_02", NULL, ADMIN1, NULL);
            (void)st;
            /* 2047 is past the test NOC's notAfter (2040), 2022 and "unknown" are inside / unchecked */
            CHECK(code == (pass == 1 ? MT_NOC_INVALID_NOC : MT_NOC_OK));
        }
    }

    /* through the real IM engine: Administer is enforced, TimeNotAccepted is Status FAILURE + cluster status 2 */
    ct_init(true);
    fx_session(S_PASE, MT_IM_AUTH_PASE, 0, 0);
    fx_session(S_CASE_OTHER, MT_IM_AUTH_CASE, 2, 0x99);
    w = req(); mt_tlv_put_u(w, mt_tlv_ctx(0), T0); mt_tlv_put_u(w, mt_tlv_ctx(1), MT_TIME_GRAN_MS);
    im_inv(S_CASE_OTHER, 120, TS, 0, w, false);
    CHECK(ct_status(MT_IM_UNSUPPORTED_ACCESS, -1) && !F.utc_calls && mt_root_utc_now(&F.r) == 0);
    w = req(); mt_tlv_put_u(w, mt_tlv_ctx(0), T0); mt_tlv_put_u(w, mt_tlv_ctx(1), MT_TIME_GRAN_MS);
    im_inv(S_CASE1, 121, TS, 0, w, false);
    CHECK(ct_status(MT_IM_SUCCESS, -1) && F.utc_calls == 1 && mt_root_utc_now(&F.r) == 700000000u);
    CHECK(mt_root_set_utc(&F.r, T0, MT_TIME_GRAN_US, MT_TIME_SRC_NONMATTER_NTP) == MT_OK);
    w = req(); mt_tlv_put_u(w, mt_tlv_ctx(0), T0); mt_tlv_put_u(w, mt_tlv_ctx(1), MT_TIME_GRAN_MS);
    im_inv(S_CASE1, 122, TS, 0, w, false);
    CHECK(ct_status(MT_IM_FAILURE, MT_TIME_CST_NOT_ACCEPTED) && F.utc_calls == 1);
    w = req(); mt_tlv_put_u(w, mt_tlv_ctx(0), T0); mt_tlv_put_u(w, mt_tlv_ctx(1), 9);
    im_inv(S_CASE1, 123, TS, 0, w, false);
    CHECK(ct_status(MT_IM_CONSTRAINT_ERROR, -1));
}
