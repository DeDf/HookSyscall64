
#include "driver.h"

ULONG64 g_KiSystemCall64;
ULONG64 g_MyKiSysCall64;

PUCHAR Trampoline;
PULONG_PTR Address;

PLONG32   SsdtTable;
ULONG_PTR SsdtTrampoline;        // FF25 XXXXXXXX
PULONG64  SsdtAddress;

PLONG32   ShadowSsdtTable;
ULONG_PTR ShadowSsdtTrampoline;  // FF25 XXXXXXXX
PULONG64  ShadowSsdtAddress;

PSERVICE_DESCRIPTOR_TABLE pMySsdt;
PSERVICE_DESCRIPTOR_TABLE_SHADOW pMyShadowSsdt;

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
	*(PLONG32)(Trampoline + 4) = Rel32;

	// cmp rsi,qword ptr [rax]
	*(PULONG_PTR)(Trampoline + 8) = 0x303B48;
	// pop rax
	*(PUCHAR)(Trampoline + 11) = 0x58;
	// ret
	*(PUCHAR)(Trampoline + 12) = 0xC3;

	// call
	*(PUCHAR)p = 0xE8;
	*(PLONG32)(p + 1) = (LONG32)(Trampoline - p - 5);

	// nop 2 bytes
	*(PUSHORT)(p + 5) = 0x9090;

	Trampoline += 13;
}
 
VOID FixOpcodeCmovaeRsiInDriver(
	ULONG_PTR pMySysCall64,
	ULONG64 Offset,
	PULONG_PTR pAddress)
{
	ULONG_PTR p = pMySysCall64 + Offset;
    LONG32 Rel32;
    ULONG_PTR DriverOffset;

    KdPrint(("found %p : cmovae rsi,qword ptr [nt!MmUserProbeAddress]\n", p));

	// push rax
	*Trampoline = 0x50;
	//mov rax, qword ptr
	*(PULONG_PTR)(Trampoline + 1) = 0x058B48;

	// rel32
	*pAddress = (ULONG_PTR)&MmUserProbeAddress;
	Rel32 = (LONG32)((PUCHAR)pAddress - Trampoline - 8);
	*(PLONG32)(Trampoline + 4) = Rel32;

	// cmovae  rsi,qword ptr [rax]
	*(PULONG_PTR)(Trampoline + 8) = 0x30430F48;
	// pop rax
	*(PUCHAR)(Trampoline + 12) = 0x58;
	// ret
	*(PUCHAR)(Trampoline + 13) = 0xC3;

	// call
	*(PUCHAR)p = 0xE8;
	*(PLONG32)(p + 1) = (LONG32)(Trampoline - p - 5);

	// nop 3 bytes
	*(PUSHORT)(p + 5) = 0x9090;
    *(PUCHAR) (p + 7) = 0x90;

	Trampoline += 14;
}
 
VOID FixOpcodeTestInDriver(
	ULONG_PTR pKiSystemCall64,
	ULONG_PTR pMySysCall64,
	ULONG64 Offset,
	PULONG_PTR pAddress)
{
	ULONG_PTR p = pMySysCall64 + Offset;
    LONG32 Rel32;

    KdPrint(("found %p : test dword ptr [nt!PerfGlobalGroupMask],40h\n", p));

	Rel32 = *(PULONG32)(p + 2);

    // push rax
    *Trampoline = 0x50;
    // mov rax, qword ptr
    *(PULONG_PTR)(Trampoline + 1) = 0x058B48;

    // rel32
    *pAddress = pKiSystemCall64 + Offset + 10 + Rel32;
    Rel32 = (LONG32)((PUCHAR)pAddress - Trampoline - 8);
    *(PLONG32)(Trampoline + 4) = Rel32;

    // test dword ptr [rax],40h
    *(PULONG_PTR)(Trampoline + 8) = 0x4000F7;
    *(PULONG_PTR)(Trampoline + 11) = 0;
    // pop rax
    *(PUCHAR)(Trampoline + 14) = 0x58;
    // ret
    *(PUCHAR)(Trampoline + 15) = 0xC3;

	// call
	*(PUCHAR)p = 0xE8;
	*(PLONG32)(p + 1) = (LONG32)(Trampoline - p - 5);

	// nop 5 bytes
	*(PULONG32)(p + 5) = 0x90909090;
    *(PUCHAR)  (p + 9) = 0x90;

    Trampoline += 16;
}

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

    memset(pMySsdt, 0 ,sizeof(SERVICE_DESCRIPTOR_TABLE_SHADOW));

	// Fill SSDT in driver
	//pMySsdt->ServiceTable  = SsdtTable;
    pMySsdt->ServiceTable  = SysSsdt->ServiceTable;
	pMySsdt->ArgumentTable = SysSsdt->ArgumentTable;
	pMySsdt->CounterTable  = SysSsdt->CounterTable;
	pMySsdt->TableSize     = SysSsdt->TableSize;

    //KdPrint(("\n===============SSDT===============\n"));

	// Fill ssdt rel32
// 	for (i = 0; i < SysSsdt->TableSize; i++)
// 	{
//         if (g_vOSVer <= OS_2003)
//             SsdtAddress[i] = ((LONG)SysSsdt->ServiceTable[i] & 0xFFFFFFF0) + (ULONG_PTR)SysSsdt->ServiceTable;
//         else
// 		    SsdtAddress[i] = ((LONG)SysSsdt->ServiceTable[i] >> 4) + (ULONG_PTR)SysSsdt->ServiceTable;
// 
//         // jmp qword ptr
//         *(PUSHORT)SsdtTrampoline = 0x25FF;
// 
//         // rel32
//         Rel32 = (LONG32)((ULONG_PTR)&SsdtAddress[i] - SsdtTrampoline - 6);
//         *(PLONG32)(SsdtTrampoline + 2) = Rel32;
// 
//         SsdtTable[i] = ((LONG)(SsdtTrampoline - (ULONG_PTR)SsdtTable)) << 4;
//         SsdtTable[i] |= SysSsdt->ServiceTable[i] & 0xF;
// 
//         SsdtTrampoline += 6;
//         //KdPrint(("%d 0x%llX\n", i, SsdtAddress[i]));
// 	}

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
	PSERVICE_DESCRIPTOR_TABLE_SHADOW SysShadowSsdt)
{
    PEPROCESS eprocess;
    KAPC_STATE ApcState;
    //
    LONG32 Rel32;
    ULONG32 i;

	if (!SysShadowSsdt)
		return STATUS_NOT_FOUND;

	eprocess = LookupAWin32Process();
	if (!eprocess)
	{
		return STATUS_NOT_FOUND;
	}
	KeStackAttachProcess(eprocess, &ApcState);  // Attach to a GUI process to obtain shadow ssdt address

	//pMyShadowSsdt->SsdtServiceTable  = SsdtTable;
    pMyShadowSsdt->SsdtServiceTable  = SysShadowSsdt->SsdtServiceTable;
	pMyShadowSsdt->SsdtArgumentTable = SysShadowSsdt->SsdtArgumentTable;
	pMyShadowSsdt->SsdtCounterTable  = SysShadowSsdt->SsdtCounterTable;
	pMyShadowSsdt->SsdtTableSize     = SysShadowSsdt->SsdtTableSize;
    //
	//pMyShadowSsdt->ServiceTable  = ShadowSsdtTable;
    pMyShadowSsdt->ServiceTable      = SysShadowSsdt->ServiceTable;
	pMyShadowSsdt->ArgumentTable     = SysShadowSsdt->ArgumentTable;
	pMyShadowSsdt->CounterTable      = SysShadowSsdt->CounterTable;
	pMyShadowSsdt->TableSize         = SysShadowSsdt->TableSize;

    //KdPrint(("\n===============ShadowSSDT===============\n"));

	// Fill shadow ssdt rel32
// 	for (i = 0; i < SysShadowSsdt->TableSize; i++)
// 	{
//         if (g_vOSVer <= OS_2003)
//             ShadowSsdtAddress[i] = ((LONG)SysShadowSsdt->ServiceTable[i] & 0xFFFFFFF0) + (ULONG_PTR)SysShadowSsdt->ServiceTable;
//         else
//             ShadowSsdtAddress[i] = ((LONG)SysShadowSsdt->ServiceTable[i] >> 4) + (ULONG_PTR)SysShadowSsdt->ServiceTable;
// 
// 		// jmp qword ptr
// 		*(PUSHORT)ShadowSsdtTrampoline = 0x25FF;
// 
// 		// rel32
// 		Rel32 = (LONG32)((ULONG_PTR)&ShadowSsdtAddress[i] - ShadowSsdtTrampoline - 6);
// 		*(PLONG32)(ShadowSsdtTrampoline + 2) = Rel32;
// 
// 		ShadowSsdtTable[i] = ((LONG)(ShadowSsdtTrampoline - (ULONG_PTR)ShadowSsdtTable)) << 4;
//         ShadowSsdtTable[i] |= SysShadowSsdt->ServiceTable[i] & 0xF;
// 
// 		ShadowSsdtTrampoline += 6;
//         //KdPrint(("%d 0x%llX\n", i, ShadowSsdtAddress[i]));
// 	}

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
		Rel32 = (LONG32)((ULONG_PTR)pMySsdt - (pMySysCall64 + leaR10Offset) - 7);
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
		RebuiltShadowSsdt((PSERVICE_DESCRIPTOR_TABLE_SHADOW)SysShadowSsdt);

		Rel32 = (LONG32)((ULONG_PTR)pMyShadowSsdt - (pMySysCall64 + leaR11Offset) - 7);
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
		Rel32 = (LONG32)((ULONG_PTR)pMyShadowSsdt+0x20 - (pMySysCall64 + leaRdiOffset) - 7);
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

        // Fix FF15 call  qword ptr [fffffa80`010320d0]
        else if (pKiSystemCall64[i] == 0xFF &&
            pKiSystemCall64[i + 1] == 0x15 )
        {
            ULONG_PTR p = pMySysCall64 + i;
            LONG32 Rel32 = *(PLONG32)(p + 2);

            *Address = Rel32 + (ULONG_PTR)pKiSystemCall64 + i + 6;
            if ( MmIsAddressValid((PVOID)(*Address)) )
            {
                KdPrint(("found %p : 0xFF15 call\n", p));
                *Address = *(PULONG_PTR)(*Address);
                *(PLONG32)(p + 2) = (LONG32)((PUCHAR)Address - p - 6);
                Address++;
            }
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

        // Fix opcode cmovae rsi,qword ptr [nt!MmUserProbeAddress]
        // Change it to call xxxxxxxx
        else if (pKiSystemCall64[i] == 0x48 &&
            pKiSystemCall64[i + 1] == 0x0f &&
            pKiSystemCall64[i + 2] == 0x43 &&
            pKiSystemCall64[i + 3] == 0x35)
        {
            FixOpcodeCmovaeRsiInDriver(
                pMySysCall64,
                i,
                Address++);
        }

        // Fix opcode test dword ptr [nt!PerfGlobalGroupMask],40h
        // Change it to a call xxxxxxxx
        else if (pKiSystemCall64[i] == 0xF7 &&
            pKiSystemCall64[i + 1] == 0x05 &&
            pKiSystemCall64[i + 6] == 0x40)
        {
            FixOpcodeTestInDriver(
                (ULONG_PTR)pKiSystemCall64,
                pMySysCall64,
                i,
                Address++);
        }

        // Fix lea r10,[nt!KeServiceDescriptorTable]
        // and lea r11,[nt!KeServiceDescriptorTableShadow]
        else if (pKiSystemCall64[i] == 0x4c &&
            pKiSystemCall64[i + 1] == 0x8d &&
            pKiSystemCall64[i + 7] == 0x4c &&
            pKiSystemCall64[i + 8] == 0x8d)
        {
            UCHAR *p = (UCHAR *)(pMySysCall64 + i + 14);

            // Save their rel32
            leaR10Offset = i;
            leaR11Offset = i + 7;

            //=======================
            *Address = (ULONG_PTR)(&pKiSystemCall64[i] + 14);
            
            // jmp qword ptr
            * p      = 0xFF;
            *(p + 1) = 0x25;
            *(PLONG32)(p + 2) = (LONG32)((PUCHAR)Address - p - 6);

            Address++;
        }

        // Fix lea rdi,[nt!KeServiceDescriptorTableShadow]
        else if (pKiSystemCall64[i] == 0x48 &&
            pKiSystemCall64[i + 1] == 0x8d &&
            pKiSystemCall64[i + 2] == 0x3d)
        {
            leaRdiOffset = i;
        }
    }

    if (!leaR10Offset || !leaR11Offset || !leaRdiOffset)
    {
        KdPrint(("Failed to initialize ssdt table!\n"));
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

ULONG_PTR InitMySyscall64()
{
    PUCHAR pKiSystemCall64 = (PUCHAR)__readmsr(0xC0000082);
    SIZE_T syscall64length = 0;
    ULONG_PTR p;
    ULONG i;

    if (!pKiSystemCall64)
        return 0;

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
        syscall64length = 0x1000 - sizeof(SERVICE_DESCRIPTOR_TABLE_SHADOW) * 2;

    p = (ULONG_PTR)ExAllocatePoolWithTag(NonPagedPool, 0x13000, 'DeDf');
    if (!p)
        return 0;
    RtlZeroMemory((PVOID)p, 0x13000);

    RtlCopyMemory((PVOID)p, pKiSystemCall64, syscall64length);
    KdPrint(("p : %p, %p, KiSystemCall64 length = %x\n",
        (PULONG_PTR)p,
        pKiSystemCall64,
        syscall64length));

    pMySsdt       = (PSERVICE_DESCRIPTOR_TABLE)        (p + 0x1000 - \
        sizeof(SERVICE_DESCRIPTOR_TABLE_SHADOW) * 2);
    pMyShadowSsdt = (PSERVICE_DESCRIPTOR_TABLE_SHADOW) (p + 0x1000 - \
        sizeof(SERVICE_DESCRIPTOR_TABLE_SHADOW));

    Trampoline           = (PUCHAR)  (p + 0x1000);
    Address              = (PULONG_PTR)(p + 0x2000);
    //
    SsdtTable            = (PLONG32) (p + 0x3000);
    SsdtTrampoline       =            p + 0x4000;
    SsdtAddress          = (PULONG64)(p + 0x5000);
    //
    ShadowSsdtTable      = (PLONG32) (p + 0x6000);
    ShadowSsdtTrampoline =            p + 0x7500;
    ShadowSsdtAddress    = (PULONG64)(p + 0x9500);

    //__debugbreak();

    // fix rel addr in our syscall.
    if ( FixMySyscall64(p, pKiSystemCall64, syscall64length) )
    {
        ExFreePool((PVOID)p);
        return 0;
    }

    return p;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    int i;

    // 遍历所有处理器
    for (i = 0; i < KeNumberProcessors; i++)
    {
        KeSetSystemAffinityThread ((KAFFINITY) ((ULONG_PTR)1 << i));  // 将代码运行在指定CPU
        __writemsr(0xC0000082, g_KiSystemCall64);
        KeRevertToUserAffinityThread ();
    }

    ExFreePool((PVOID)g_MyKiSysCall64);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    int i;

	DriverObject->DriverUnload = DriverUnload;

	g_MyKiSysCall64 = InitMySyscall64();
    if (g_MyKiSysCall64)
    {
        g_KiSystemCall64 = __readmsr(0xC0000082);

        // 遍历所有处理器
        for (i = 0; i < KeNumberProcessors; i++)
        {
            KeSetSystemAffinityThread ((KAFFINITY) ((ULONG_PTR)1 << i));  // 将代码运行在指定CPU
            __writemsr(0xC0000082, g_MyKiSysCall64);
            KeRevertToUserAffinityThread ();
        }

        return STATUS_SUCCESS;
    }
    else
	    return STATUS_UNSUCCESSFUL;
}

