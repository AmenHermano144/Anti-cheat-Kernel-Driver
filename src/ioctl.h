#pragma once

#include "core.h"

#define IOCTL_AC_PING         CORE_AC_CTL(0x801)
#define IOCTL_AC_BOOTSTRAP    CORE_AC_CTL(0x802)
#define IOCTL_AC_KEY_EXCHANGE CORE_AC_CTL(0x803)
#define IOCTL_AC_MUX          CORE_AC_CTL(0x850)

DRIVER_DISPATCH CoreIoctlCreateClose;
DRIVER_DISPATCH CoreIoctlDispatch;
