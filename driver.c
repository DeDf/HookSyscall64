
#include "driver.h"

ULONG_PTR TrampolineInDriver = (ULONG_PTR)_syscall64 + 0x1000; // 0x100
ULONG_PTR SsdtTrampolineInDriver = (ULONG_PTR)_syscall64 + 0x1100; // 0x1200
ULONG_PTR ShadowSsdtTrampolineInDriver = (ULONG_PTR)_syscall64 + 0x2300; // 0x1E00
ULONG_PTR CallR10InDriver, CallR10InMdl, CallR10InSystem;
PULONG_PTR CallR10;

ULONG_PTR TrampolineInMdl;
ULONG_PTR SsdtTrampolineInMdl;
ULONG_PTR ShadowSsdtTrampolineInMdl;

ULONG64 PtrAddress[0x100];
PVOID Syscall64Pointer;


LONG SsdtTable[0x200];
ULONG64 SsdtAddress[0x200];

LONG ShadowSsdtTable[0x500];
ULONG64 ShadowSsdtAddress[0x500];

SERVICE_DESCRIPTOR_TABLE SsdtInDriver;
ULONG64 Nop[4];
SERVICE_DESCRIPTOR_TABLE_SHADOW ShadowSsdtInDriver;




VOID FixOpcodeCmpRsiInDriver(ULONG_PTR AddressInDriver,
	ULONG_PTR AddressInSystem,
	ULONG_PTR AddressInMdl,
	ULONG64 Offset,
	PULONG_PTR Ptr)
{
	ULONG_PTR MdlOffset = AddressInMdl + Offset;
    ULONG32 Rel32;
    ULONG_PTR DriverOffset;

	DbgPrint("From %p found cmp rsi, qword ptr [nt!MmUserProbeAddress]\n", MdlOffset);

	// push rax
	*(PULONG_PTR)TrampolineInMdl = 0x50;
	//mov rax, qword ptr
	*(PULONG_PTR)(TrampolineInMdl + 1) = 0x058B48;

	// rel32
	*(PULONG_PTR)*Ptr = (ULONG64)&MmUserProbeAddress;
	Rel32 = (ULONG32)(*Ptr - (TrampolineInDriver + 8));
	*(PULONG32)(TrampolineInMdl + 4) = Rel32;

	// cmp rsi,qword ptr [rax]
	*(PULONG_PTR)(TrampolineInMdl + 8) = 0x303B48;
	// pop rax
	*(PUCHAR)(TrampolineInMdl + 11) = 0x58;
	// ret
	*(PUCHAR)(TrampolineInMdl + 12) = 0xC3;

	// call
	*(PUCHAR)MdlOffset = 0xE8;


	DriverOffset = AddressInDriver + Offset;
	Rel32 = (ULONG32)(TrampolineInDriver - (DriverOffset + 5));

	RtlCopyMemory((PULONG_PTR)(MdlOffset + 1), &Rel32, 4);

	// nop 2 bytes
	memset((PULONG_PTR)(MdlOffset + 5), 0x90, 2);

	TrampolineInDriver += 13;
	TrampolineInMdl += 13;
	*Ptr += 8;
}

VOID FixOpcodeCmovaeRsiInDriver(ULONG_PTR AddressInDriver,
	ULONG_PTR AddressInSystem,
	ULONG_PTR AddressInMdl,
	ULONG64 Offset,
	PULONG_PTR Ptr)
{
	ULONG_PTR MdlOffset = AddressInMdl + Offset;
    ULONG32 Rel32;
    ULONG_PTR DriverOffset;

	DbgPrint("From %p found cmovae rsi,qword ptr [nt!MmUserProbeAddress]\n", MdlOffset);

	// push rax
	*(PULONG_PTR)TrampolineInMdl = 0x50;
	//mov rax, qword ptr
	*(PULONG_PTR)(TrampolineInMdl + 1) = 0x058B48;

	// rel32
	*(PULONG_PTR)*Ptr = (ULONG64)&MmUserProbeAddress;
	Rel32 = (ULONG32)(*Ptr - (TrampolineInDriver + 8));
	*(PULONG32)(TrampolineInMdl + 4) = Rel32;

	// cmovae  rsi,qword ptr [rax]
	*(PULONG_PTR)(TrampolineInMdl + 8) = 0x30430F48;
	// pop rax
	*(PUCHAR)(TrampolineInMdl + 12) = 0x58;
	// ret
	*(PUCHAR)(TrampolineInMdl + 13) = 0xC3;

	// call
	*(PUCHAR)MdlOffset = 0xE8;

	DriverOffset = AddressInDriver + Offset;
	Rel32 = (ULONG32)(TrampolineInDriver - (DriverOffset + 5));

	RtlCopyMemory((PULONG_PTR)(MdlOffset + 1), &Rel32, 4);

	// nop 3 bytes
	memset((PULONG_PTR)(MdlOffset + 5), 0x90, 3);

	TrampolineInDriver += 14;
	TrampolineInMdl += 14;
	*Ptr += 8;
}

VOID FixOpcodeTestInDriver(ULONG_PTR AddressInDriver,
	ULONG_PTR AddressInSystem,
	ULONG_PTR AddressInMdl,
	ULONG64 Offset,
	PULONG_PTR Ptr)
{
	ULONG_PTR MdlOffset = AddressInMdl + Offset;
    ULONG32 Rel32;
    ULONG_PTR DriverOffset;

	DbgPrint("From %p found test dword ptr [nt!PerfGlobalGroupMask],40h\n", MdlOffset);

	Rel32 = *(PULONG32)(MdlOffset + 2);

	// push rax
	*(PULONG_PTR)TrampolineInMdl = 0x50;
	// mov rax, qword ptr
	*(PULONG_PTR)(TrampolineInMdl + 1) = 0x058B48;

	// rel32
	*(PULONG_PTR)*Ptr = AddressInSystem + Offset + 10 + Rel32;
	Rel32 = (ULONG32)(*Ptr - (TrampolineInDriver + 8));
	*(PULONG32)(TrampolineInMdl + 4) = Rel32;

	// test qword ptr [rax],40h
	*(PULONG_PTR)(TrampolineInMdl + 8) = 0x4000F748;
	*(PULONG_PTR)(TrampolineInMdl + 12) = '\x00\x00\x00';
	// pop rax
	*(PUCHAR)(TrampolineInMdl + 15) = 0x58;
	// ret
	*(PUCHAR)(TrampolineInMdl + 16) = 0xC3;

	// call
	*(PUCHAR)MdlOffset = 0xE8;

	DriverOffset = AddressInDriver + Offset;
	Rel32 = (ULONG32)(TrampolineInDriver - (DriverOffset + 5));

	RtlCopyMemory((PULONG_PTR)(MdlOffset + 1), &Rel32, 4);

	// nop 5 bytes
	memset((PULONG_PTR)(MdlOffset + 5), 0x90, 5);

	TrampolineInMdl += 17;
	TrampolineInDriver += 17;
	*Ptr += 8;
}

VOID FixOpcodeCallInDriver(ULONG_PTR AddressInDriver,
	ULONG_PTR AddressInSystem,
	ULONG_PTR p,
	ULONG64 Offset,
	PULONG_PTR Ptr)
{
	ULONG_PTR cp = p + Offset;
    ULONG32 Rel32;
    ULONG_PTR TargetAddress;

	KdPrint(("0xE8 call found at %p\n", cp));

	Rel32 = *(PULONG32)(cp + 1);

	// rel32+next
	if (Rel32 > 0xffff0000)
		TargetAddress = (Rel32 ^ 0xffffffff00000000) + AddressInSystem + Offset + 5;
	else
		TargetAddress = Rel32 + AddressInSystem + Offset + 5;

	if (MmIsAddressValid((PVOID)TargetAddress))
	{
        ULONG_PTR DriverOffset;

		// jmp qword ptr
		*(PUCHAR)TrampolineInMdl = 0xFF;
		*(PUCHAR)(TrampolineInMdl + 1) = 0x25;

		// target - opcode rel32
		*(PULONG_PTR)*Ptr = TargetAddress;
		Rel32 = (ULONG32)(*Ptr - (TrampolineInDriver + 6));
		*(PULONG32)(TrampolineInMdl + 2) = Rel32;

		// call rel32
		DriverOffset = AddressInDriver + Offset;
		Rel32 = (ULONG32)(TrampolineInDriver - (DriverOffset + 5));

		*(PULONG32)(cp + 1) = Rel32;

		TrampolineInMdl += 6;
		TrampolineInDriver += 6;
		*Ptr += 8;
	}
	else
	{
        DbgPrint("From %p Call - MmIsAddressValid() failed : %p\n", cp, TargetAddress);
	}
}

NTSTATUS FixSyscall64RelativeAddress(ULONG_PTR MdlVa, ULONG_PTR pKiSystemCall64, SIZE_T Length)
{
	NTSTATUS status = STATUS_SUCCESS;

	PUCHAR syscall = (PUCHAR)MdlVa;

	ULONG_PTR Ptr = (ULONG64)&PtrAddress; // size = 0x71

										  // lea r10,[nt!KeServiceDescriptorTable]
										  // lea r11,[nt!KeServiceDescriptorTableShadow]
										  // lea rdi,[nt!KeServiceDescriptorTableShadow]
	ULONG64 leaR10Offset = 0, leaR11Offset = 0, leaRdiOffset = 0;
    ULONG i;

	// KeServiceDescriptorTable 0x20
	// KeServiceDescriptorTableShadow 0x40

	// SSDT
	// 0x1b9 * (6 bytes jmp + 8 bytes address) = 0x181e
	// ~0x200 = 0x1c00
	// total = 0x1c20

	// Shadow SSDT
	// 0x46a * (6 bytes jmp + 8 bytes address) = 0x3dcc
	// ~0x500 = 0x4600
	// total = 0x4640

	typedef VOID(*_handler)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG64, PULONG_PTR);

	_handler Handler = NULL;

	for (i = 0; i < Length; i++)
	{
		// Fix opcode call
		// Change it to jmp ptr xxxxxxxx
		if (syscall[i] == 0xE8)
		{
			Handler = FixOpcodeCallInDriver;
		}

		// Fix opcode cmp rsi, qword ptr [nt!MmUserProbeAddress]
		// Change it to a call xxxxxxxx
		else if (syscall[i] == 0x48 &&
			 syscall[i + 1] == 0x3B &&
			 syscall[i + 2] == 0x35)
		{
			Handler = FixOpcodeCmpRsiInDriver;
		}

		// Fix opcode cmovae rsi,qword ptr [nt!MmUserProbeAddress]
		// Change it to call xxxxxxxx
		else if (syscall[i] == 0x48 &&
			 syscall[i + 1] == 0x0f &&
			 syscall[i + 2] == 0x43 &&
			 syscall[i + 3] == 0x35)
		{
			Handler = FixOpcodeCmovaeRsiInDriver;
		}

		// Fix opcode test dword ptr [nt!PerfGlobalGroupMask],40h
		// Change it to a call xxxxxxxx
		else if (syscall[i] == 0xF7 &&
			 syscall[i + 1] == 0x05 &&
			 syscall[i + 6] == 0x40)
		{
			Handler = FixOpcodeTestInDriver;
		}

		// Fix lea r10,[nt!KeServiceDescriptorTable]
		// and lea r11,[nt!KeServiceDescriptorTableShadow]
		else if (syscall[i] == 0x4c &&
			 syscall[i + 1] == 0x8d &&
			 syscall[i + 7] == 0x4c &&
			 syscall[i + 8] == 0x8d)
		{
			// Save their rel32
			leaR10Offset = i;
			leaR11Offset = i + 7;
		}

		// Fix lea rdi,[nt!KeServiceDescriptorTableShadow]
		else if (syscall[i] == 0x48 &&
			 syscall[i + 1] == 0x8d &&
			 syscall[i + 2] == 0x3d)
		{
			leaRdiOffset = i;
		}

		// Find call r10
		else if (syscall[i] == 0x41 &&
			 syscall[i + 1] == 0xff &&
			 syscall[i + 2] == 0xd2 &&
			 syscall[i + 3] == 0x65 &&
			 syscall[i + 4] == 0xff)
		{
			DbgPrint("Call r10 found!\n");
			CallR10InDriver = (ULONG_PTR)_syscall64 + i;
			CallR10InMdl = MdlVa + i;
			CallR10InSystem = pKiSystemCall64 + i;
			CallR10 = &CallR10InSystem;
		}

		if (Handler)
        {
			Handler((ULONG_PTR)_syscall64,
				pKiSystemCall64,
				(ULONG_PTR)MdlVa,
				i,
				&Ptr);
			Handler = NULL;
		}
	}

	if (!leaR10Offset || !leaR11Offset || !leaRdiOffset)
	{
		DbgPrint("Failed to initialize ssdt table!\n");
		return STATUS_NOT_FOUND;
	}
	else
	{
		RebuildSystemServiceTable((ULONG_PTR)_syscall64,
			pKiSystemCall64,
			(ULONG_PTR)MdlVa,
			leaR10Offset,
			leaR11Offset,
			leaRdiOffset);
	}
	return status;
}

NTSTATUS RebuiltSsdt(ULONG_PTR SysSsdtAddress)
{
	PSERVICE_DESCRIPTOR_TABLE SysSsdt = (PSERVICE_DESCRIPTOR_TABLE)SysSsdtAddress;
    LONG TableRel;
    ULONG32 Rel32;
    USHORT index;

	if (!SysSsdt)
		return STATUS_NOT_FOUND;

	// Fill SSDT in driver
	SsdtInDriver.ServiceTable = (PLONG)&SsdtTable;
	SsdtInDriver.ArgumentTable = SysSsdt->ArgumentTable;
	SsdtInDriver.CounterTable = SysSsdt->CounterTable;
	SsdtInDriver.TableSize = SysSsdt->TableSize;

	// Fill ssdt rel32
	for (index = 0;index < SysSsdt->TableSize;index++)
	{
		// address = ssdt[index] >> 4 + table_address
		TableRel = (LONG)SysSsdt->ServiceTable[index];
		SsdtAddress[index] = (TableRel >> 4) + (ULONG_PTR)SysSsdt->ServiceTable;

		if (SsdtAddress[index] == (ULONG_PTR)NtSetInformationThread ||
			SsdtAddress[index] == (ULONG_PTR)NtQueryInformationThread)
		{
			DbgPrint("Some functions found. Address = %p\n", SsdtAddress[index]);
			__debugbreak();

			// mov r10,qword ptr
			*(PULONG_PTR)(SsdtTrampolineInMdl) = 0x158B4C;

			// rel32
			Rel32 = (ULONG32)((ULONG_PTR)&SsdtAddress[index] - (SsdtTrampolineInDriver + 7));
			*(PULONG32)(SsdtTrampolineInMdl + 3) = Rel32;

			// add rsp, 8
			*(PULONG_PTR)(SsdtTrampolineInMdl + 7) = 0x08C48348;

			// jmp qword ptr nt!KiSystemServiceCopyEnd+0x10
			*(PULONG_PTR)(SsdtTrampolineInMdl + 11) = 0x25FF;

			// rel32
			Rel32 = (ULONG32)((ULONG_PTR)CallR10 - (SsdtTrampolineInDriver + 17));
			*(PULONG32)(SsdtTrampolineInMdl + 13) = Rel32;

			TableRel = ((LONG)(SsdtTrampolineInDriver - (ULONG_PTR)&SsdtTable)) << 4;
			SsdtTable[index] = TableRel;

			SsdtTrampolineInMdl += 17;
			SsdtTrampolineInDriver += 17;
		}
		else
		{
			// jmp qword ptr
			*(PULONG_PTR)SsdtTrampolineInMdl = 0x25FF;

			// rel32
			Rel32 = (ULONG32)((ULONG_PTR)&SsdtAddress[index] - (SsdtTrampolineInDriver + 6));
			*(PULONG32)(SsdtTrampolineInMdl + 2) = Rel32;

			TableRel = ((LONG)(SsdtTrampolineInDriver - (ULONG_PTR)&SsdtTable)) << 4;
			SsdtTable[index] = TableRel;

			SsdtTrampolineInMdl += 6;
			SsdtTrampolineInDriver += 6;
		}

	}
	return STATUS_SUCCESS;
}

NTSTATUS RebuiltShadowSsdt(ULONG_PTR SysSsdtAddress,
	ULONG_PTR SysShadowSsdtAddress)
{
	PSERVICE_DESCRIPTOR_TABLE SysSsdt = (PSERVICE_DESCRIPTOR_TABLE)SysSsdtAddress;
	PSERVICE_DESCRIPTOR_TABLE_SHADOW SysShadowSsdt = (PSERVICE_DESCRIPTOR_TABLE_SHADOW)SysShadowSsdtAddress;
    PEPROCESS eprocess;
    KAPC_STATE ApcState;
    LONG TableRel;
    ULONG32 Rel32;
    USHORT index;

	if (!SysSsdt || !SysShadowSsdt)
		return STATUS_NOT_FOUND;

	LookupAWin32Process(&eprocess);
	if (!eprocess)
	{
		return STATUS_NOT_FOUND;
	}

	// Attach to a GUI process to obtain shadow ssdt address
	
	KeStackAttachProcess(eprocess, &ApcState);

	// SSDT in Shadow SSDT
	ShadowSsdtInDriver.SsdtServiceTable = (PLONG)&SsdtTable;
	ShadowSsdtInDriver.SsdtArgumentTable = SysSsdt->ArgumentTable;
	ShadowSsdtInDriver.SsdtCounterTable = SysSsdt->CounterTable;
	ShadowSsdtInDriver.SsdtTableSize = SysSsdt->TableSize;

	// Shadow SSDT
	ShadowSsdtInDriver.ServiceTable = (PLONG)&ShadowSsdtTable;
	ShadowSsdtInDriver.ArgumentTable = SysShadowSsdt->ArgumentTable;
	ShadowSsdtInDriver.CounterTable = SysShadowSsdt->CounterTable;
	ShadowSsdtInDriver.TableSize = SysShadowSsdt->TableSize;

	

	// Fill shadow ssdt rel32
	for (index = 0;index < SysShadowSsdt->TableSize;index++)
	{
		// address = ssdt[index] >> 4 + table_address
		TableRel = (LONG)SysShadowSsdt->ServiceTable[index];

		// jmp qword ptr
		*(PULONG_PTR)ShadowSsdtTrampolineInMdl = 0x25FF;
		ShadowSsdtAddress[index] = (TableRel >> 4) + (ULONG_PTR)SysShadowSsdt->ServiceTable;

		// rel32
		Rel32 = (ULONG32)((ULONG_PTR)&ShadowSsdtAddress[index] - (ShadowSsdtTrampolineInDriver + 6));
		*(PULONG32)(ShadowSsdtTrampolineInMdl + 2) = Rel32;

		// Fill our new service table.
		TableRel = ((LONG)(ShadowSsdtTrampolineInDriver - (ULONG_PTR)&ShadowSsdtTable)) << 4;

		ShadowSsdtTable[index] = TableRel;

		ShadowSsdtTrampolineInDriver += 6;
		ShadowSsdtTrampolineInMdl += 6;
	}

	KeUnstackDetachProcess(&ApcState);

	return STATUS_SUCCESS;
}

VOID LookupAWin32Process(PEPROCESS *eprocess)
{
	PEPROCESS EProcess;
    USHORT pid;

	for (pid = 4;;pid += 4)
	{
		if (PsLookupProcessByProcessId((HANDLE)pid, &EProcess) == STATUS_SUCCESS)
		{
			if (PsGetProcessWin32Process(EProcess))
			{
				*eprocess = EProcess;
				break;
			}
		}
	}
}

// Many bugs
NTSTATUS RebuildSystemServiceTable(ULONG_PTR DriverAddress,
	ULONG_PTR SystemAddress,
	ULONG_PTR MdlAddress,
	ULONG_PTR leaR10Offset,
	ULONG_PTR leaR11Offset,
	ULONG_PTR leaRdiOffset)
{
    ULONG32 Rel32;
    ULONG_PTR SysSsdt;
    ULONG_PTR SysShadowSsdt;

	if (!leaR10Offset || !leaR11Offset || !leaRdiOffset || !DriverAddress || !SystemAddress || !MdlAddress)
		return STATUS_NOT_FOUND;

	

	// Obtain SSDT address
	Rel32 = *(PULONG32)(MdlAddress + leaR10Offset + 3);
	SysSsdt = SystemAddress + leaR10Offset + 7 + Rel32;
	if (Rel32)
	{
		RebuiltSsdt(SysSsdt);
		Rel32 = (ULONG32)((ULONG_PTR)&SsdtInDriver - (DriverAddress + leaR11Offset));
		*(PULONG32)(MdlAddress + leaR10Offset + 3) = Rel32;
	}
	else
	{
		return STATUS_NOT_FOUND;
	}

	// and Shadow SSDT
	Rel32 = *(PULONG32)(MdlAddress + leaR11Offset + 3);
	SysShadowSsdt = SystemAddress + leaR11Offset + 7 + Rel32;
	if (Rel32)
	{
		RebuiltShadowSsdt(SysSsdt, SysShadowSsdt);
		Rel32 = (ULONG32)((ULONG_PTR)&ShadowSsdtInDriver - (DriverAddress + leaR11Offset + 7));
		*(PULONG32)(MdlAddress + leaR11Offset + 3) = Rel32;
	}
	else
	{
		return STATUS_NOT_FOUND;
	}

	// Fix lea rdi, 
	Rel32 = *(PULONG32)(MdlAddress + leaRdiOffset + 3);
	if (Rel32)
	{
		Rel32 = (ULONG32)((ULONG_PTR)&ShadowSsdtInDriver - (DriverAddress + leaRdiOffset + 7));
		*(PULONG32)(MdlAddress + leaRdiOffset + 3) = Rel32;
	}
	else
	{
		return STATUS_NOT_FOUND;
	}

	return STATUS_SUCCESS;
}

NTSTATUS InitializeFakeSyscall()
{
    PUCHAR pKiSystemCall64 = (PUCHAR)__readmsr(0xC0000082);
    PUCHAR syscall64end    = 0;
    SIZE_T syscall64length = 0;
    ULONG_PTR p;
    SHORT i;

    __debugbreak();

    if (!pKiSystemCall64)
        return STATUS_NOT_FOUND;

    // 0x1000 may be enough?
    for (i = 0; i < 0x1000; i++)
    {
        if (*(pKiSystemCall64 + i) == 0xE9)
        {
            // end suffix
            if (*(pKiSystemCall64 + i + 1) == 0x59 &&
                *(pKiSystemCall64 + i + 2) == 0xFD &&
                *(pKiSystemCall64 + i + 3) == 0xFF &&
                *(pKiSystemCall64 + i + 4) == 0xFF)
            {
                syscall64end = pKiSystemCall64 + i + 5;
                syscall64length = syscall64end - pKiSystemCall64;
                break;
            }
        }
    }

    if (!syscall64end)
        return STATUS_NOT_FOUND;

    KdPrint(("_syscall64 length = %x\n", syscall64length));

    p = (ULONG_PTR)ExAllocatePoolWithTag(NonPagedPool, syscall64length+10, 'DeDf');

    RtlCopyMemory((PVOID)p, pKiSystemCall64, syscall64length);

    TrampolineInMdl           = p + 0x1000;
    SsdtTrampolineInMdl       = p + 0x1100;
    ShadowSsdtTrampolineInMdl = p + 0x2300;

    // fix rel addr in our syscall.
    FixSyscall64RelativeAddress(p,
        (ULONG_PTR)pKiSystemCall64,
        syscall64length);

    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	if (Syscall64Pointer)
		ExFreePool(Syscall64Pointer);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	DriverObject->DriverUnload = DriverUnload;

	InitializeFakeSyscall();

	return STATUS_SUCCESS;
}

