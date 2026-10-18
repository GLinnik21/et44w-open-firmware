# Library rules. Each <dir>/lib.mk is included with $(d) = its directory, appends its lib names to
# LIBS and sets, per lib:
#   <name>_SRC     C sources
#   <name>_INC     include dirs, seen by the lib itself and by libs that list it in their _DEPS
#   <name>_DEFS    -D flags that are part of the lib's interface (seen the same way as _INC)
#   <name>_DEPS    libs whose headers this lib may include; not transitive, list each one
#   <name>_CFLAGS  extra compiler flags (after OUR_CFLAGS, so they can relax warnings)
#   <name>_POST    command run on each object after compiling it ($@ = the object); use `=`, not `:=`
# A lib only sees the headers it declares, so e.g. a pure-C lib with no "sdk" dependency fails to
# compile if it reaches for SDK headers.

obj = $(patsubst %.c,$(OUT)/obj/%.o,$(subst ../,__/,$(1)))

define lib_rules
$(1)_OBJ := $$(call obj,$$($(1)_SRC))
$$($(1)_OBJ): LIB_FLAGS := $$(OUR_CFLAGS) $$($(1)_CFLAGS) \
    $$(foreach x,$(1) $$($(1)_DEPS),$$($$(x)_DEFS) $$(addprefix -I,$$($$(x)_INC)))
$$($(1)_OBJ): LIB_POST = $$($(1)_POST)
OBJS += $$($(1)_OBJ)
endef

define compile
	@mkdir -p $(dir $@)
	@echo "  CC   $<"
	@$(CC) $(CFLAGS) $(LIB_FLAGS) -c $< -o $@
	$(if $(LIB_POST),@$(LIB_POST))
endef

$(OUT)/obj/%.o: %.c
	$(compile)
# Sources outside firmware/ (e.g. APP=apps/thermostat-matter) build under $(OUT)/obj/__/.
$(OUT)/obj/__/%.o: ../%.c
	$(compile)
