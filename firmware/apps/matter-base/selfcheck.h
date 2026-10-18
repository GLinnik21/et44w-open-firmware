// Device self-check for the probe build: is a local TCP service still accepting connections?
#pragma once
#include <stdbool.h>
#include <stdint.h>
bool selfcheck_tcp_answers(uint16_t port); // connect to 127.0.0.1:port within 5 s, then close
