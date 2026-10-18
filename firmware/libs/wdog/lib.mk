# Hardware watchdog fed by a task just above idle: a fault spin, interrupts left off or a CPU hog becomes a reset.
# A task that blocks forever doesn't starve the feeder, so it isn't caught. See include/wdog.h.
LIBS += wdog
wdog_INC  := $(d)/include
wdog_SRC  := $(wildcard $(d)/src/*.c)
wdog_DEPS := sdk
