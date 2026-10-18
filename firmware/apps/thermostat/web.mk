# The web page (web/index.html) compiled in as a byte array: $(OUT)/gen/web_page.h, for web.c.
# Included by this app's lib.mk and by ../thermostat-matter/lib.mk; TM_WEB_DIR is this directory.
$(OUT)/gen/web_page.h: $(TM_WEB_DIR)/web/index.html tools/embed_c.py
	@mkdir -p $(dir $@)
	python3 tools/embed_c.py $< $@ WebPage
$(call obj,$(TM_WEB_DIR)/web.c): $(OUT)/gen/web_page.h
