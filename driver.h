#pragma once

#include <ntifs.h>

typedef struct _SERVICE_DESCRIPTOR_TABLE {

	PLONG32 ServiceTable;
	PULONG  CounterTable;
	ULONG   TableSize;
	PUCHAR  ArgumentTable;

} SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;

typedef struct _SERVICE_DESCRIPTOR_TABLE_SHADOW {
	PLONG32 SsdtServiceTable;
	PULONG  SsdtCounterTable;
	ULONG	SsdtTableSize;
	PUCHAR  SsdtArgumentTable;

	PLONG32 ServiceTable;
	PULONG  CounterTable;
	ULONG	TableSize;
	PUCHAR  ArgumentTable;
} SERVICE_DESCRIPTOR_TABLE_SHADOW, *PSERVICE_DESCRIPTOR_TABLE_SHADOW;

PVOID PsGetProcessWin32Process(PEPROCESS Process);
