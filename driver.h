#pragma once

#include <ntifs.h>

typedef struct _SERVICE_DESCRIPTOR_TABLE {

	PLONG   ServiceTable;
	PULONG  CounterTable;
	ULONG   TableSize;
	PUCHAR  ArgumentTable;

} SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;

typedef struct _SERVICE_DESCRIPTOR_TABLE_SHADOW {
	PLONG   SsdtServiceTable;
	PULONG  SsdtCounterTable;
	ULONG	SsdtTableSize;
	PUCHAR  SsdtArgumentTable;

	PLONG   ServiceTable;
	PULONG  CounterTable;
	ULONG	TableSize;
	PUCHAR  ArgumentTable;
} SERVICE_DESCRIPTOR_TABLE_SHADOW, *PSERVICE_DESCRIPTOR_TABLE_SHADOW;


NTKERNELAPI NTSTATUS NtQueryInformationThread(
	IN      HANDLE          ThreadHandle,
	IN      THREADINFOCLASS ThreadInformationClass,
	OUT     PVOID           ThreadInformation,
	IN      ULONG           ThreadInformationLength,
	OUT     PULONG          ReturnLength OPTIONAL
	);


NTKERNELAPI NTSTATUS NtQuerySystemInformation(
	ULONG                    SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength);


NTKERNELAPI PVOID PsGetProcessWin32Process(PEPROCESS Process);

//
// From assembly
//
VOID _syscall64();
VOID OpcodeJmpMemory();
VOID SsdtOpcodeJmpMemory();
VOID ShadowSsdtOpcodeJmpMemory();

NTSTATUS InitializeFakeSyscall();

NTSTATUS FixSyscall64RelativeAddress(ULONG_PTR MdlVa,
	ULONG_PTR SyscallOrigin,
	SIZE_T Length);

VOID FixOpcodeCmpRsiInDriver(ULONG_PTR AddressInDriver,
	ULONG_PTR AddressInSystem,
	ULONG_PTR AddressInMdl,
	ULONG64 Offset,
	PULONG_PTR Ptr);

VOID FixOpcodeCallInDriver(ULONG_PTR AddressInDriver,
	ULONG_PTR AddressInSystem,
	ULONG_PTR AddressInMdl,
	ULONG64 Offset,
	PULONG_PTR Ptr);

VOID FixOpcodeCmovaeRsiInDriver(ULONG_PTR AddressInDriver,
	ULONG_PTR AddressInSystem,
	ULONG_PTR AddressInMdl,
	ULONG64 Offset,
	PULONG_PTR Ptr);

VOID FixOpcodeTestInDriver(ULONG_PTR AddressInDriver,
	ULONG_PTR AddressInSystem,
	ULONG_PTR AddressInMdl,
	ULONG64 Offset,
	PULONG_PTR Ptr);

NTSTATUS RebuildSystemServiceTable(ULONG_PTR DriverAddress,
	ULONG_PTR SystemAddress,
	ULONG_PTR MdlAddress,
	ULONG_PTR leaR10Offset,
	ULONG_PTR leaR11Offset,
	ULONG_PTR leaRdiOffset);

VOID LookupAWin32Process(PEPROCESS *eprocess);

NTSTATUS RebuiltShadowSsdt(ULONG_PTR SysSsdtAddress,
	ULONG_PTR SysShadowSsdtAddress);
