
#include "driver.h"

ULONG_PTR CallR10InDriver, CallR10InMdl, CallR10InSystem;
PULONG_PTR CallR10;

PUCHAR Trampoline;
PULONG_PTR Address;

PLONG32   SsdtTable;
ULONG_PTR SsdtTrampoline;        // FF25 XXXXXXXX
PULONG64  SsdtAddress;

PLONG32   ShadowSsdtTable;
ULONG_PTR ShadowSsdtTrampoline;  // FF25 XXXXXXXX
PULONG64  ShadowSsdtAddress;

SERVICE_DESCRIPTOR_TABLE MySsdt;
SERVICE_DESCRIPTOR_TABLE_SHADOW MyShadowSsdt;

VOID FixOpcodeCmpRsiInDriver(
	ULONG_PTR pMySysCall64,
	ULONG64 Offset,
	PULONG_PTR pAddress)
{
	ULONG_PTR p = pMySysCall64 + Offset;
    LONG32 Rel32;

    KdPrint(("found %p : cmp rsi, qword ptr [nt!MmUserProbeAddress]\n", p));

	// push rax
	*Trampoline = 0x50;
	//mov rax, qword ptr
	*(PULONG_PTR)(Trampoline + 1) = 0x058B48;

	// rel32
	*pAddress = (ULONG_PTR)&MmUserProbeAddress;
	Rel32 = (LONG32)((PUCHAR)pAddress - Trampoline - 8);
	*(PULONG32)(Trampoline + 4) = Rel32;

	// cmp rsi,qword ptr [rax]
	*(PULONG_PTR)(Trampoline + 8) = 0x303B48;
	// pop rax
	*(PUCHAR)(Trampoline + 11) = 0x58;
	// ret
	*(PUCHAR)(Trampoline + 12) = 0xC3;

	// call
	*(PUCHAR)p = 0xE8;

	Rel32 = (LONG32)(Trampoline - p - 5);

	*(PLONG32)(p + 1) = (LONG32)(Trampoline - p - 5);

	// nop 2 bytes
	*(PUSHORT)(p + 5) = 0x9090;

	Trampoline += 13;
}
 
// VOID FixOpcodeCmovaeRsiInDriver(ULONG_PTR AddressInDriver,
// 	ULONG_PTR AddressInSystem,
// 	ULONG_PTR AddressInMdl,
// 	ULONG64 Offset,
// 	PULONG_PTR Ptr)
// {
// 	ULONG_PTR MdlOffset = AddressInMdl + Offset;
//     ULONG32 Rel32;
//     ULONG_PTR DriverOffset;
// 
// 	DbgPrint("From %p found cmovae rsi,qword ptr [nt!MmUserProbeAddress]\n", MdlOffset);
// 
// 	// push rax
// 	*(PULONG_PTR)Trampolines = 0x50;
// 	//mov rax, qword ptr
// 	*(PULONG_PTR)(Trampolines + 1) = 0x058B48;
// 
// 	// rel32
// 	*(PULONG_PTR)*Ptr = (ULONG64)&MmUserProbeAddress;
// 	Rel32 = (ULONG32)(*Ptr - (TrampolineInDriver + 8));
// 	*(PULONG32)(Trampolines + 4) = Rel32;
// 
// 	// cmovae  rsi,qword ptr [rax]
// 	*(PULONG_PTR)(Trampolines + 8) = 0x30430F48;
// 	// pop rax
// 	*(PUCHAR)(Trampolines + 12) = 0x58;
// 	// ret
// 	*(PUCHAR)(Trampolines + 13) = 0xC3;
// 
// 	// call
// 	*(PUCHAR)MdlOffset = 0xE8;
// 
// 	DriverOffset = AddressInDriver + Offset;
// 	Rel32 = (ULONG32)(TrampolineInDriver - (DriverOffset + 5));
// 
// 	RtlCopyMemory((PULONG_PTR)(MdlOffset + 1), &Rel32, 4);
// 
// 	// nop 3 bytes
// 	memset((PULONG_PTR)(MdlOffset + 5), 0x90, 3);
// 
// 	TrampolineInDriver += 14;
// 	Trampolines += 14;
// 	*Ptr += 8;
// }
// 
// VOID FixOpcodeTestInDriver(ULONG_PTR AddressInDriver,
// 	ULONG_PTR AddressInSystem,
// 	ULONG_PTR AddressInMdl,
// 	ULONG64 Offset,
// 	PULONG_PTR Ptr)
// {
// 	ULONG_PTR MdlOffset = AddressInMdl + Offset;
//     ULONG32 Rel32;
//     ULONG_PTR DriverOffset;
// 
// 	DbgPrint("From %p found test dword ptr [nt!PerfGlobalGroupMask],40h\n", MdlOffset);
// 
// 	Rel32 = *(PULONG32)(MdlOffset + 2);
// 
// 	// push rax
// 	*(PULONG_PTR)Trampolines = 0x50;
// 	// mov rax, qword ptr
// 	*(PULONG_PTR)(Trampolines + 1) = 0x058B48;
// 
// 	// rel32
// 	*(PULONG_PTR)*Ptr = AddressInSystem + Offset + 10 + Rel32;
// 	Rel32 = (ULONG32)(*Ptr - (TrampolineInDriver + 8));
// 	*(PULONG32)(Trampolines + 4) = Rel32;
// 
// 	// test qword ptr [rax],40h
// 	*(PULONG_PTR)(Trampolines + 8) = 0x4000F748;
// 	*(PULONG_PTR)(Trampolines + 12) = '\x00\x00\x00';
// 	// pop rax
// 	*(PUCHAR)(Trampolines + 15) = 0x58;
// 	// ret
// 	*(PUCHAR)(Trampolines + 16) = 0xC3;
// 
// 	// call
// 	*(PUCHAR)MdlOffset = 0xE8;
// 
// 	DriverOffset = AddressInDriver + Offset;
// 	Rel32 = (ULONG32)(TrampolineInDriver - (DriverOffset + 5));
// 
// 	RtlCopyMemory((PULONG_PTR)(MdlOffset + 1), &Rel32, 4);
// 
// 	// nop 5 bytes
// 	memset((PULONG_PTR)(MdlOffset + 5), 0x90, 5);
// 
// 	Trampolines += 17;
// 	TrampolineInDriver += 17;
// 	*Ptr += 8;
// }

VOID FixOpcodeCallInDriver(
	ULONG_PTR pKiSystemCall64,
	ULONG_PTR pMySysCall64,
	ULONG64 Offset,
	PULONG_PTR pAddress)
{
	ULONG_PTR p = pMySysCall64 + Offset;
    LONG32 Rel32;
    ULONG_PTR TargetAddress;

    KdPrint(("found %p : 0xE8 call\n", p));

	Rel32 = *(PLONG32)(p + 1);

	TargetAddress = Rel32 + pKiSystemCall64 + Offset + 5;

	if (MmIsAddressValid((PVOID)TargetAddress))
	{
		// target - opcode rel32
		*pAddress = TargetAddress;

        // jmp qword ptr
        * Trampoline      = 0xFF;
        *(Trampoline + 1) = 0x25;

		Rel32 = (LONG32)((PUCHAR)pAddress - Trampoline - 6);
		*(PLONG32)(Trampoline + 2) = Rel32;

		*(PLONG32)(p + 1) = (LONG32)(Trampoline - p - 5);

        Trampoline += 6;
	}
	else
	{
        KdPrint(("From %p Call - MmIsAddressValid() failed : %p\n", p, TargetAddress));
	}
}


NTSTATUS RebuiltSsdt(PSERVICE_DESCRIPTOR_TABLE SysSsdt)
{
    LONG32 Rel32;
    ULONG32 i;

	if (!SysSsdt)
		return STATUS_NOT_FOUND;

	// Fill SSDT in driver
	MySsdt.ServiceTable  = (PLONG)&SsdtTable;
	MySsdt.ArgumentTable = SysSsdt->ArgumentTable;
	MySsdt.CounterTable  = SysSsdt->CounterTable;
	MySsdt.TableSize     = SysSsdt->TableSize;

	// Fill ssdt rel32
	for (i = 0; i < SysSsdt->TableSize; i++)
	{
		SsdtAddress[i] = ((LONG)SysSsdt->ServiceTable[i] >> 4) + (ULONG_PTR)SysSsdt->ServiceTable;

        // jmp qword ptr
        *(PUSHORT)SsdtTrampoline = 0x25FF;

        // rel32
        Rel32 = (LONG32)((ULONG_PTR)&SsdtAddress[i] - SsdtTrampoline - 6);
        *(PLONG32)(SsdtTrampoline + 2) = Rel32;

        SsdtTable[i] = ((LONG)(SsdtTrampoline - (ULONG_PTR)SsdtTable)) << 4;

        SsdtTrampoline += 6;
	}

	return STATUS_SUCCESS;
}

PEPROCESS LookupAWin32Process()
{
    PEPROCESS EProcess;
    ULONG pid;

    for (pid = 4; pid < 5000; pid += 4)
    {
        if (PsLookupProcessByProcessId((HANDLE)pid, &EProcess) == STATUS_SUCCESS)
        {
            if (PsGetProcessWin32Process(EProcess))
            {
                return EProcess;
            }
        }
    }

    return NULL;
}

NTSTATUS
RebuiltShadowSsdt(
    PSERVICE_DESCRIPTOR_TABLE SysSsdt,
	PSERVICE_DESCRIPTOR_TABLE SysShadowSsdt)
{
    PEPROCESS eprocess;
    KAPC_STATE ApcState;
    //
    LONG32 Rel32;
    ULONG32 i;

	if (!SysSsdt || !SysShadowSsdt)
		return STATUS_NOT_FOUND;

	eprocess = LookupAWin32Process();
	if (!eprocess)
	{
		return STATUS_NOT_FOUND;
	}
	KeStackAttachProcess(eprocess, &ApcState);  // Attach to a GUI process to obtain shadow ssdt address

	// SSDT in Shadow SSDT
	MyShadowSsdt.SsdtServiceTable  = (PLONG)&SsdtTable;
	MyShadowSsdt.SsdtArgumentTable = SysSsdt->ArgumentTable;
	MyShadowSsdt.SsdtCounterTable  = SysSsdt->CounterTable;
	MyShadowSsdt.SsdtTableSize     = SysSsdt->TableSize;

	// Shadow SSDT
	MyShadowSsdt.ServiceTable  = (PLONG)&ShadowSsdtTable;
	MyShadowSsdt.ArgumentTable = SysShadowSsdt->ArgumentTable;
	MyShadowSsdt.CounterTable  = SysShadowSsdt->CounterTable;
	MyShadowSsdt.TableSize     = SysShadowSsdt->TableSize;

	// Fill shadow ssdt rel32
	for (i = 0; i < SysShadowSsdt->TableSize; i++)
	{
        ShadowSsdtAddress[i] = ((LONG)SysShadowSsdt->ServiceTable[i] >> 4) + (ULONG_PTR)SysShadowSsdt->ServiceTable;

		// jmp qword ptr
		*(PUSHORT)ShadowSsdtTrampoline = 0x25FF;

		// rel32
		Rel32 = (LONG32)((ULONG_PTR)&ShadowSsdtAddress[i] - ShadowSsdtTrampoline - 6);
		*(PLONG32)(ShadowSsdtTrampoline + 2) = Rel32;

		ShadowSsdtTable[i] = ((LONG)(ShadowSsdtTrampoline - (ULONG_PTR)ShadowSsdtTable)) << 4;

		ShadowSsdtTrampoline += 6;
	}

	KeUnstackDetachProcess(&ApcState);

	return STATUS_SUCCESS;
}

NTSTATUS RebuildSystemServiceTable(
	ULONG_PTR pKiSystemCall64,
	ULONG_PTR pMySysCall64,
	ULONG_PTR leaR10Offset,
	ULONG_PTR leaR11Offset,
	ULONG_PTR leaRdiOffset)
{
    LONG32 Rel32;
    ULONG_PTR SysSsdt;
    ULONG_PTR SysShadowSsdt;

	if (!leaR10Offset || !leaR11Offset || !leaRdiOffset || !pKiSystemCall64 || !pMySysCall64)
		return STATUS_NOT_FOUND;

	// Obtain SSDT address
	Rel32 = *(PLONG32)(pKiSystemCall64 + leaR10Offset + 3);
	SysSsdt = pKiSystemCall64 + leaR10Offset + 7 + Rel32;
	if (Rel32)
	{
		RebuiltSsdt((PSERVICE_DESCRIPTOR_TABLE)SysSsdt);
		Rel32 = (LONG32)((ULONG_PTR)&MySsdt - (pMySysCall64 + leaR11Offset) - 7);
		*(PLONG32)(pMySysCall64 + leaR10Offset + 3) = Rel32;
	}
	else
	{
		return STATUS_NOT_FOUND;
	}

    // and Shadow SSDT
	Rel32 = *(PLONG32)(pKiSystemCall64 + leaR11Offset + 3);
	SysShadowSsdt = pKiSystemCall64 + leaR11Offset + 7 + Rel32;
	if (Rel32)
	{
		RebuiltShadowSsdt(
            (PSERVICE_DESCRIPTOR_TABLE)SysSsdt,
            (PSERVICE_DESCRIPTOR_TABLE)SysShadowSsdt);

		Rel32 = (LONG32)((ULONG_PTR)&MyShadowSsdt - (pMySysCall64 + leaR11Offset) - 7);
		*(PLONG32)(pMySysCall64 + leaR11Offset + 3) = Rel32;
	}
	else
	{
		return STATUS_NOT_FOUND;
	}

	// Fix lea rdi, 
	Rel32 = *(PLONG32)(pMySysCall64 + leaRdiOffset + 3);
	if (Rel32)
	{
		Rel32 = (LONG32)((ULONG_PTR)&MyShadowSsdt - (pMySysCall64 + leaRdiOffset) - 7);
		*(PLONG32)(pMySysCall64 + leaRdiOffset + 3) = Rel32;
	}
	else
	{
		return STATUS_NOT_FOUND;
	}

	return STATUS_SUCCESS;
}

NTSTATUS FixMySyscall64(ULONG_PTR pMySysCall64, PUCHAR pKiSystemCall64, SIZE_T Length)
{
    // lea r10,[nt!KeServiceDescriptorTable]
    // lea r11,[nt!KeServiceDescriptorTableShadow]
    // lea rdi,[nt!KeServiceDescriptorTableShadow]
    ULONG64 leaR10Offset = 0, leaR11Offset = 0, leaRdiOffset = 0;
    ULONG64 i;

    typedef VOID (*_handler)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG64, PULONG_PTR);

    _handler Handler = NULL;

    for (i = 0; i < Length; i++)
    {
        // Fix opcode call
        // Change it to jmp ptr xxxxxxxx
        if (pKiSystemCall64[i] == 0xE8)
        {
            FixOpcodeCallInDriver(
                (ULONG_PTR)pKiSystemCall64,
                pMySysCall64,
                i,
                Address++);
        }

        // Fix opcode cmp rsi, qword ptr [nt!MmUserProbeAddress]
        // Change it to a call xxxxxxxx
        else if (pKiSystemCall64[i] == 0x48 &&
            pKiSystemCall64[i + 1] == 0x3B &&
            pKiSystemCall64[i + 2] == 0x35)
        {
            FixOpcodeCmpRsiInDriver(
                pMySysCall64,
                i,
                Address++);
        }
// 
//         // Fix opcode cmovae rsi,qword ptr [nt!MmUserProbeAddress]
//         // Change it to call xxxxxxxx
//         else if (syscall[i] == 0x48 &&
//             syscall[i + 1] == 0x0f &&
//             syscall[i + 2] == 0x43 &&
//             syscall[i + 3] == 0x35)
//         {
//             Handler = FixOpcodeCmovaeRsiInDriver;
//         }
// 
//         // Fix opcode test dword ptr [nt!PerfGlobalGroupMask],40h
//         // Change it to a call xxxxxxxx
//         else if (syscall[i] == 0xF7 &&
//             syscall[i + 1] == 0x05 &&
//             syscall[i + 6] == 0x40)
//         {
//             Handler = FixOpcodeTestInDriver;
//         }

        // Fix lea r10,[nt!KeServiceDescriptorTable]
        // and lea r11,[nt!KeServiceDescriptorTableShadow]
        else if (pKiSystemCall64[i] == 0x4c &&
            pKiSystemCall64[i + 1] == 0x8d &&
            pKiSystemCall64[i + 7] == 0x4c &&
            pKiSystemCall64[i + 8] == 0x8d)
        {
            // Save their rel32
            leaR10Offset = i;
            leaR11Offset = i + 7;
        }

        // Fix lea rdi,[nt!KeServiceDescriptorTableShadow]
        else if (pKiSystemCall64[i] == 0x48 &&
            pKiSystemCall64[i + 1] == 0x8d &&
            pKiSystemCall64[i + 2] == 0x3d)
        {
            leaRdiOffset = i;
        }

        // Find call r10
//         else if (syscall[i] == 0x41 &&
//             syscall[i + 1] == 0xff &&
//             syscall[i + 2] == 0xd2 &&
//             syscall[i + 3] == 0x65 &&
//             syscall[i + 4] == 0xff)
//         {
//             DbgPrint("Call r10 found!\n");
//             CallR10InDriver = (ULONG_PTR)_syscall64 + i;
//             CallR10InMdl = pMySysCall64 + i;
//             CallR10InSystem = pKiSystemCall64 + i;
//             CallR10 = &CallR10InSystem;
//         }

//         if (Handler)
//         {
//             Handler((ULONG_PTR)_syscall64,
//                 pKiSystemCall64,
//                 (ULONG_PTR)pMySysCall64,
//                 i,
//                 pAddress);
//             Handler = NULL;
//         }
    }

    if (!leaR10Offset || !leaR11Offset || !leaRdiOffset)
    {
        DbgPrint("Failed to initialize ssdt table!\n");
        return STATUS_NOT_FOUND;
    }
    else
    {
        RebuildSystemServiceTable(
            (ULONG_PTR)pKiSystemCall64,
            pMySysCall64,
            leaR10Offset,
            leaR11Offset,
            leaRdiOffset);
    }

    return STATUS_SUCCESS;
}

NTSTATUS InitMySyscall64()
{
    PUCHAR pKiSystemCall64 = (PUCHAR)__readmsr(0xC0000082);
    SIZE_T syscall64length = 0;
    ULONG_PTR p;
    ULONG i;

    if (!pKiSystemCall64)
        return STATUS_NOT_FOUND;

    // 0x1000 may be enough?
    for (i = 0; i < 0x1000; i++)
    {
        if (*(pKiSystemCall64 + i) == 0xE9)
        {
            if (*(pKiSystemCall64 + i + 1) == 0x59 &&
                *(pKiSystemCall64 + i + 2) == 0xFD &&
                *(pKiSystemCall64 + i + 3) == 0xFF &&
                *(pKiSystemCall64 + i + 4) == 0xFF)
            {
                syscall64length = i + 5;
                break;
            }
        }
    }

    if (!syscall64length)
        return STATUS_NOT_FOUND;

    p = (ULONG_PTR)ExAllocatePoolWithTag(NonPagedPool, 0x13000, 'DeDf');
    if (!p)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory((PVOID)p, 0x13000);
    RtlCopyMemory((PVOID)p, pKiSystemCall64, syscall64length);

    KdPrint(("p : %p, KiSystemCall64 length = %x\n", (PULONG_PTR)p, syscall64length));
    __debugbreak();

    Trampoline          = (PUCHAR)  (p + 0x1000);
    Address              = (PULONG_PTR)(p + 0x2000);
    //
    SsdtTable            = (PLONG32) (p + 0x3000);
    SsdtTrampoline       =            p + 0x4000;
    SsdtAddress          = (PULONG64)(p + 0x5000);
    //
    ShadowSsdtTable      = (PLONG32) (p + 0x6000);
    ShadowSsdtTrampoline =            p + 0x7500;
    ShadowSsdtAddress    = (PULONG64)(p + 0x9500);

    // fix rel addr in our syscall.
    if ( FixMySyscall64(p, pKiSystemCall64, syscall64length) )
        ExFreePool((PVOID)p);
    else
        ExFreePool((PVOID)p);
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	DriverObject->DriverUnload = DriverUnload;

	InitMySyscall64();

	return STATUS_UNSUCCESSFUL;
}

