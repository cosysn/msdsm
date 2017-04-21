#pragma once
/*++

Copyright (C) 2004  Microsoft Corporation

Module Name:

trace.h

Abstract:

Header file included by the Microsoft Device Specific Module (DSM).

This file contains Windows tracing related defines.

Environment:

kernel mode only

Notes:

--*/

#define TracePrintEx(Fmt, ...)  \
do\
{\
	 DbgPrintEx(DPFLTR_FASTFAT_ID, DPFLTR_ERROR_LEVEL, Fmt, __VA_ARGS__); \
}while (0)


