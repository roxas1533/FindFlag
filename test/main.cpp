#include <Windows.h>
#include <iostream>
#pragma pack(push)
#pragma pack(1)
#define EM(a) __asm __emit (a)

#define X64_Start_with_CS(_cs) \
{ \
	EM(0x6A) EM(_cs)                     \
	EM(0xE8) EM(0) EM(0) EM(0) EM(0)     \
	EM(0x83) EM(4) EM(0x24) EM(5)        \
	EM(0xCB)                             \
}

#define X64_End_with_CS(_cs) \
{ \
	EM(0xE8) EM(0) EM(0) EM(0) EM(0)     \
	EM(0xC7) EM(0x44) EM(0x24) EM(4)     \
	EM(_cs) EM(0) EM(0) EM(0)            \
	EM(0x83) EM(4) EM(0x24) EM(0xD)      \
	EM(0xCB)                             \
}

#define X64_Start() X64_Start_with_CS(0x33)
#define X64_End() X64_End_with_CS(0x23)
#define REX_W EM(0x48) __asm

union reg64
{
	DWORD64 v;
	DWORD dw[2];
};

#define X64_Push(r) EM(0x48 | ((r) >> 3)) EM(0x50 | ((r) & 7))
#define X64_Pop(r) EM(0x48 | ((r) >> 3)) EM(0x58 | ((r) & 7))

template <class T>
struct _LIST_ENTRY_T
{
	T Flink;
	T Blink;
};

template <class T>
struct _UNICODE_STRING_T
{
	union
	{
		struct
		{
			WORD Length;
			WORD MaximumLength;
		};
		T dummy;
	};
	T Buffer;
};

template <class T>
struct _NT_TIB_T
{
	T ExceptionList;
	T StackBase;
	T StackLimit;
	T SubSystemTib;
	T FiberData;
	T ArbitraryUserPointer;
	T Self;
};

template <class T>
struct _CLIENT_ID
{
	T UniqueProcess;
	T UniqueThread;
};

template <class T>
struct _TEB_T_
{
	_NT_TIB_T<T> NtTib;
	T EnvironmentPointer;
	_CLIENT_ID<T> ClientId;
	T ActiveRpcHandle;
	T ThreadLocalStoragePointer;
	T ProcessEnvironmentBlock;
	DWORD LastErrorValue;
	DWORD CountOfOwnedCriticalSections;
	T CsrClientThread;
	T Win32ThreadInfo;
	DWORD User32Reserved[26];
};

template <class T>
struct _LDR_DATA_TABLE_ENTRY_T
{
	_LIST_ENTRY_T<T> InLoadOrderLinks;
	_LIST_ENTRY_T<T> InMemoryOrderLinks;
	_LIST_ENTRY_T<T> InInitializationOrderLinks;
	T DllBase;
	T EntryPoint;
	union
	{
		DWORD SizeOfImage;
		T dummy01;
	};
	_UNICODE_STRING_T<T> FullDllName;
	_UNICODE_STRING_T<T> BaseDllName;
	DWORD Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		_LIST_ENTRY_T<T> HashLinks;
		struct
		{
			T SectionPointer;
			T CheckSum;
		};
	};
	union
	{
		T LoadedImports;
		DWORD TimeDateStamp;
	};
	T EntryPointActivationContext;
	T PatchInformation;
	_LIST_ENTRY_T<T> ForwarderLinks;
	_LIST_ENTRY_T<T> ServiceTagLinks;
	_LIST_ENTRY_T<T> StaticLinks;
	T ContextInformation;
	T OriginalBase;
	_LARGE_INTEGER LoadTime;
};

template <class T>
struct _PEB_LDR_DATA_T
{
	DWORD Length;
	DWORD Initialized;
	T SsHandle;
	_LIST_ENTRY_T<T> InLoadOrderModuleList;
	_LIST_ENTRY_T<T> InMemoryOrderModuleList;
	_LIST_ENTRY_T<T> InInitializationOrderModuleList;
	T EntryInProgress;
	DWORD ShutdownInProgress;
	T ShutdownThreadId;
};

template <class T, class NGF, int A>
struct _PEB_T
{
	union
	{
		struct
		{
			BYTE InheritedAddressSpace;
			BYTE ReadImageFileExecOptions;
			BYTE BeingDebugged;
			BYTE BitField;
		};
		T dummy01;
	};
	T Mutant;
	T ImageBaseAddress;
	T Ldr;
	T ProcessParameters;
	T SubSystemData;
	T ProcessHeap;
	T FastPebLock;
	T AtlThunkSListPtr;
	T IFEOKey;
	T CrossProcessFlags;
	T UserSharedInfoPtr;
	DWORD SystemReserved;
	DWORD AtlThunkSListPtr32;
	T ApiSetMap;
	T TlsExpansionCounter;
	T TlsBitmap;
	DWORD TlsBitmapBits[2];
	T ReadOnlySharedMemoryBase;
	T HotpatchInformation;
	T ReadOnlyStaticServerData;
	T AnsiCodePageData;
	T OemCodePageData;
	T UnicodeCaseTableData;
	DWORD NumberOfProcessors;
	union
	{
		DWORD NtGlobalFlag;
		NGF dummy02;
	};
	LARGE_INTEGER CriticalSectionTimeout;
	T HeapSegmentReserve;
	T HeapSegmentCommit;
	T HeapDeCommitTotalFreeThreshold;
	T HeapDeCommitFreeBlockThreshold;
	DWORD NumberOfHeaps;
	DWORD MaximumNumberOfHeaps;
	T ProcessHeaps;
	T GdiSharedHandleTable;
	T ProcessStarterHelper;
	T GdiDCAttributeList;
	T LoaderLock;
	DWORD OSMajorVersion;
	DWORD OSMinorVersion;
	WORD OSBuildNumber;
	WORD OSCSDVersion;
	DWORD OSPlatformId;
	DWORD ImageSubsystem;
	DWORD ImageSubsystemMajorVersion;
	T ImageSubsystemMinorVersion;
	T ActiveProcessAffinityMask;
	T GdiHandleBuffer[A];
	T PostProcessInitRoutine;
	T TlsExpansionBitmap;
	DWORD TlsExpansionBitmapBits[32];
	T SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	T pShimData;
	T AppCompatInfo;
	_UNICODE_STRING_T<T> CSDVersion;
	T ActivationContextData;
	T ProcessAssemblyStorageMap;
	T SystemDefaultActivationContextData;
	T SystemAssemblyStorageMap;
	T MinimumStackCommit;
	T FlsCallback;
	_LIST_ENTRY_T<T> FlsListHead;
	T FlsBitmap;
	DWORD FlsBitmapBits[4];
	T FlsHighIndex;
	T WerRegistrationData;
	T WerShipAssertPtr;
	T pContextData;
	T pImageHeaderHash;
	T TracingFlags;
};

typedef _LDR_DATA_TABLE_ENTRY_T<DWORD> LDR_DATA_TABLE_ENTRY32;
typedef _LDR_DATA_TABLE_ENTRY_T<DWORD64> LDR_DATA_TABLE_ENTRY64;

typedef _TEB_T_<DWORD> TEB32;
typedef _TEB_T_<DWORD64> TEB64;

typedef _PEB_LDR_DATA_T<DWORD> PEB_LDR_DATA32;
typedef _PEB_LDR_DATA_T<DWORD64> PEB_LDR_DATA64;

typedef _PEB_T<DWORD, DWORD64, 34> PEB32;
typedef _PEB_T<DWORD64, DWORD, 30> PEB64;

class CMemPtr
{
private:
	void** m_ptr;
	bool watchActive;

public:
	CMemPtr(void** ptr) : m_ptr(ptr), watchActive(true) {}

	~CMemPtr()
	{
		if (*m_ptr && watchActive)
		{
			free(*m_ptr);
			*m_ptr = 0;
		}
	}

	void disableWatch() { watchActive = false; }
};

#define WATCH(ptr) CMemPtr watch_##ptr((void**)&ptr)

#define DISABLE_WATCH(ptr) watch_##ptr.disableWatch()

DWORD64 GetModuleHandle64(const wchar_t* lpModuleName);

#pragma warning(pop)

void getMem64(void* dstMem, DWORD64 srcMem, size_t sz)
{
	if ((nullptr == dstMem) || (0 == srcMem) || (0 == sz))
		return;

	reg64 _src = { srcMem };
	__asm
	{
		X64_Start()
		push   edi
		push   esi
		mov    edi, dstMem
		REX_W mov    esi, _src.dw[0]
		mov    ecx, sz
		mov    eax, ecx
		and eax, 3
		shr    ecx, 2
		rep    movsd
		test   eax, eax
		je     _move_0
		cmp    eax, 1
		je     _move_1
		movsw
		cmp    eax, 2
		je     _move_0
	_move_1:
		movsb
	_move_0:
		pop    esi
		pop    edi
		X64_End();
	}
}

bool cmpMem64(void* dstMem, DWORD64 srcMem, size_t sz)
{
	if ((nullptr == dstMem) || (0 == srcMem) || (0 == sz))
		return false;

	bool result = false;
	reg64 _src = { srcMem };
	__asm
	{
		X64_Start();

		;// below code is compiled as x86 inline asm, but it is executed as x64 code
		;// that's why it need sometimes REX_W() macro, right column contains detailed
		;// transcription how it will be interpreted by CPU

		push   edi;// push      rdi
		push   esi;// push      rsi
		;//
		mov    edi, dstMem;// mov       edi, dword ptr [dstMem]       ; high part of RDI is zeroed
		REX_W mov    esi, _src.dw[0];// mov       rsi, qword ptr [_src]
		mov    ecx, sz;// mov       ecx, dword ptr [sz]           ; high part of RCX is zeroed
		;//
		mov    eax, ecx;// mov       eax, ecx
		and eax, 3;// and       eax, 3
		shr    ecx, 2;// shr       ecx, 2
		;//
		repe   cmpsd;// repe cmps dword ptr [rsi], dword ptr [rdi]
		jnz     _ret_false;// jnz       _ret_false
		;//
		test   eax, eax;// test      eax, eax
		je     _move_0;// je        _move_0
		cmp    eax, 1;// cmp       eax, 1
		je     _move_1;// je        _move_1
		;//
		cmpsw;// cmps      word ptr [rsi], word ptr [rdi]
		jnz     _ret_false;// jnz       _ret_false
		cmp    eax, 2;// cmp       eax, 2
		je     _move_0;// je        _move_0
		;//
	_move_1:;//
		cmpsb;// cmps      byte ptr [rsi], byte ptr [rdi]
		jnz     _ret_false;// jnz       _ret_false
		;//
	_move_0:;//
		mov    result, 1;// mov       byte ptr [result], 1
		;//
	_ret_false:;//
		pop    esi;// pop      rsi
		pop    edi;// pop      rdi

		X64_End();
	}

	return result;
}

DWORD64 getTEB64()
{
	reg64 reg;
	reg.v = 0;

	X64_Start();
	X64_Push(12);
	__asm pop reg.dw[0]
	X64_End();
	return reg.v;
}

DWORD64 getNTDLL64()
{
	static DWORD64 ntdll64 = 0;
	if (0 != ntdll64)
		return ntdll64;

	ntdll64 = GetModuleHandle64(L"ntdll.dll");
	return ntdll64;
}

DWORD64 getLdrGetProcedureAddress()
{
	DWORD64 modBase = getNTDLL64();
	if (0 == modBase)
		return 0;

	IMAGE_DOS_HEADER idh;
	getMem64(&idh, modBase, sizeof(idh));

	IMAGE_NT_HEADERS64 inh;
	getMem64(&inh, modBase + idh.e_lfanew, sizeof(IMAGE_NT_HEADERS64));

	IMAGE_DATA_DIRECTORY& idd = inh.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	if (0 == idd.VirtualAddress)
		return 0;

	IMAGE_EXPORT_DIRECTORY ied;
	getMem64(&ied, modBase + idd.VirtualAddress, sizeof(ied));

	DWORD* rvaTable = (DWORD*)malloc(sizeof(DWORD) * ied.NumberOfFunctions);
	if (nullptr == rvaTable)
		return 0;
	WATCH(rvaTable);
	getMem64(rvaTable, modBase + ied.AddressOfFunctions, sizeof(DWORD) * ied.NumberOfFunctions);

	WORD* ordTable = (WORD*)malloc(sizeof(WORD) * ied.NumberOfFunctions);
	if (nullptr == ordTable)
		return 0;
	WATCH(ordTable);
	getMem64(ordTable, modBase + ied.AddressOfNameOrdinals, sizeof(WORD) * ied.NumberOfFunctions);

	DWORD* nameTable = (DWORD*)malloc(sizeof(DWORD) * ied.NumberOfNames);
	if (nullptr == nameTable)
		return 0;
	WATCH(nameTable);
	getMem64(nameTable, modBase + ied.AddressOfNames, sizeof(DWORD) * ied.NumberOfNames);

	for (DWORD i = 0; i < ied.NumberOfFunctions; i++)
	{
		if (!cmpMem64((void*)"LdrGetProcedureAddress", modBase + nameTable[i], sizeof("LdrGetProcedureAddress")))
			continue;
		else
			return modBase + rvaTable[ordTable[i]];
	}
	return 0;
}

DWORD64 X64Call(DWORD64 func, int argC, ...)
{
	va_list args;
	va_start(args, argC);

	reg64 _rcx = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };

	reg64 _rdx = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
	reg64 _r8 = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
	reg64 _r9 = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
	reg64 _rax = { 0 };

	reg64 restArgs = { (DWORD64)&va_arg(args, DWORD64) };

	// conversion to QWORD for easier use in inline assembly
	reg64 _argC = { (DWORD64)argC };
	DWORD back_esp = 0;
	WORD back_fs = 0;

	__asm
	{
		;// reset FS segment, to properly handle RFG
		mov    back_fs, fs
			mov    eax, 0x2B
			mov    fs, ax

			;// keep original esp in back_esp variable
		mov    back_esp, esp

			and esp, 0xFFFFFFF0

			X64_Start();

		REX_W mov    ecx, _rcx.dw[0];// mov     rcx, qword ptr [_rcx]
		REX_W mov    edx, _rdx.dw[0];// mov     rdx, qword ptr [_rdx]
		push   _r8.v;// push    qword ptr [_r8]
		X64_Pop(8); ;// pop     r8
		push   _r9.v;// push    qword ptr [_r9]
		X64_Pop(9); ;// pop     r9

		REX_W mov    eax, _argC.dw[0];// mov     rax, qword ptr [_argC]
		;// final stack adjustment, according to the
		;//
		;// number of arguments above 4
		;//
		test   al, 1;// test    al, 1
		jnz    _no_adjust;// jnz     _no_adjust
		sub    esp, 8;// sub     rsp, 8
	_no_adjust:;//
		;//
		push   edi;// push    rdi
		REX_W mov    edi, restArgs.dw[0];// mov     rdi, qword ptr [restArgs]
		;//
		;// put rest of arguments on the stack
		;//
		REX_W test   eax, eax;// test    rax, rax
		jz     _ls_e;// je      _ls_e
		REX_W lea    edi, dword ptr[edi + 8 * eax - 8];// lea     rdi, [rdi + rax*8 - 8]
		;//
	_ls:;//
		REX_W test   eax, eax;// test    rax, rax
		jz     _ls_e;// je      _ls_e
		push   dword ptr[edi];// push    qword ptr [rdi]
		REX_W sub    edi, 8;// sub     rdi, 8
		REX_W sub    eax, 1;// sub     rax, 1
		jmp    _ls;// jmp     _ls
	_ls_e:;//
		;//
		;// create stack space for spilling registers   ;//
		REX_W sub    esp, 0x20;// sub     rsp, 20h
		;//
		call   func;// call    qword ptr [func]
		;//
		;// cleanup stack                               ;//
		REX_W mov    ecx, _argC.dw[0];// mov     rcx, qword ptr [_argC]
		REX_W lea    esp, dword ptr[esp + 8 * ecx + 0x20];// lea     rsp, [rsp + rcx*8 + 20h]
		;//
		pop    edi;// pop     rdi
		;//
// set return value                             ;//

		REX_W mov    _rax.dw[0], eax;// mov     qword ptr [_rax], rax

		X64_End();

		mov    ax, ds
			mov    ss, ax
			mov    esp, back_esp

			;// restore FS segment
		mov    ax, back_fs
			mov    fs, ax
	}

	return _rax.v;
}
DWORD64 A_SHAFinal;
DWORD64 A_SHAInit;
DWORD64 A_SHAUpdate;
DWORD64 strcmp2;
DWORD64 st;
char temp[100];

void k() {
	std::cout << (PVOID)temp << "\n";
	reg64 _sdd = { 0x692047415f4c5f46 };
	reg64 _tt = { (DWORD64)temp };
	reg64 _tt2 = { 0x7975366e38542073 };
	if (X64Call(st, 2, (DWORD64)"aa", (DWORD64)"\n\0\1"))
		exit(0);
	__asm {
		X64_Start()
		REX_W mov  eax, _sdd.dw[0]
		REX_W mov  ebx, _tt.dw[0]
		REX_W mov   dword ptr[ebx], eax
		REX_W mov  eax, _tt2.dw[0]
		REX_W mov   dword ptr[ebx + 8], eax
		X64_End()
		mov dword ptr[temp + 16], 0x41357a45
	}
	printf("%s", temp);
	while (1);
}

DWORD64 X64Call2(DWORD64 func, int argC, ...)
{
	va_list args;
	va_start(args, argC);

	reg64 _rcx = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };

	reg64 _rdx = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
	reg64 _r8 = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
	reg64 _r9 = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
	reg64 _rax = { 0 };

	reg64 restArgs = { (DWORD64)&va_arg(args, DWORD64) };

	reg64 _argC = { (DWORD64)argC };
	DWORD back_esp = 0;
	WORD back_fs = 0;
	__asm
	{
		mov    back_fs, fs
		mov    eax, 0x2B
		mov    fs, ax
		mov    back_esp, esp
		and esp, 0xFFFFFFF0
		X64_Start()
		REX_W mov    ecx, _rcx.dw[0]
		REX_W mov    edx, _rdx.dw[0]
		push   _r8.v
		X64_Pop(8)
		push   _r9.v
		X64_Pop(9)
		REX_W mov    eax, _argC.dw[0]
		test   al, 1
		jnz    _no_adjust
		sub    esp, 8
		_no_adjust:
		push   edi
			REX_W mov    edi, restArgs.dw[0]
			REX_W test   eax, eax
			jz     _ls_e
			REX_W lea    edi, dword ptr[edi + 8 * eax - 8]
			_ls :
			REX_W test   eax, eax
			jz     _ls_e
			push   dword ptr[edi]
			REX_W sub    edi, 8
			REX_W sub    eax, 1
			jmp    _ls
			_ls_e :
		REX_W sub    esp, 0x20
			call   func
			REX_W mov    ecx, _argC.dw[0]
			REX_W lea    esp, dword ptr[esp + 8 * ecx + 0x20]
			pop    edi
			REX_W mov    _rax.dw[0], eax;
		X64_End()
			mov    ax, ds
			mov    ss, ax
			mov    esp, back_esp
			mov    ax, back_fs
			mov    fs, ax
	}
	if (_rax.v == 0) {
		k();
	}
	return _rax.v;
}

DWORD64 GetProcAddress64(DWORD64 hModule, const char* funcName)
{
	static DWORD64  _LdrGetProcedureAddress = 0;
	if (0 == _LdrGetProcedureAddress)
	{
		_LdrGetProcedureAddress = getLdrGetProcedureAddress();

		if (0 == _LdrGetProcedureAddress)
			return 0;
	}
	_UNICODE_STRING_T<DWORD64> fName = { 0 };
	fName.Buffer = (DWORD64)funcName;
	fName.Length = strlen(funcName);
	fName.MaximumLength = fName.Length + 1;

	DWORD64 funcRet = 0;
	X64Call(_LdrGetProcedureAddress, 4, (DWORD64)hModule, (DWORD64)&fName, (DWORD64)0, (DWORD64)&funcRet);

	return funcRet;
}

DWORD64 GetModuleHandle64(const wchar_t* lpModuleName)
{
	TEB64 teb64;
	getMem64(&teb64, getTEB64(), sizeof(TEB64));

	PEB64 peb64;
	getMem64(&peb64, teb64.ProcessEnvironmentBlock, sizeof(PEB64));

	PEB_LDR_DATA64 ldr;
	getMem64(&ldr, peb64.Ldr, sizeof(PEB_LDR_DATA64));

	DWORD64 LastEntry = peb64.Ldr + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList);
	LDR_DATA_TABLE_ENTRY64 head;
	head.InLoadOrderLinks.Flink = ldr.InLoadOrderModuleList.Flink;
	do
	{
		getMem64(&head, head.InLoadOrderLinks.Flink, sizeof(LDR_DATA_TABLE_ENTRY64));

		wchar_t* tempBuf = (wchar_t*)malloc(head.BaseDllName.MaximumLength);
		if (nullptr == tempBuf)
			return 0;
		WATCH(tempBuf);
		getMem64(tempBuf, head.BaseDllName.Buffer, head.BaseDllName.MaximumLength);

		if (0 == _wcsicmp(lpModuleName, tempBuf))
			return head.DllBase;
	} while (head.InLoadOrderLinks.Flink != LastEntry);

	return 0;
}

#  define SHA_LONG unsigned int
typedef struct SHAstate_st {
	ULONG flag;
	CHAR hash[20];
	ULONG state[5];
	ULONG count[2];
	CHAR buffer[64];
} SHA_CTX;

typedef struct ans {
	const DWORD64 temp0 = 0x2A069ED0A4ED1071;
	const DWORD64 temp1 = 0xAC72A5B090A3E4A5;
	const DWORD temp3 = 0x20022C0D;
};
void e() {
	std::string temp;
	std::cout << "ENTER FIRST PASS\n";
	std::cin >> temp;
	ans s;
	SHA_CTX sha_ctx = { 0 };
	unsigned char digest[20];
	X64Call(A_SHAInit, 1, (DWORD64)&sha_ctx);
	X64Call(A_SHAUpdate, 3, (DWORD64)&sha_ctx, (DWORD64)temp.c_str(), (DWORD64)temp.length());
	X64Call(A_SHAFinal, 2, (DWORD64)&sha_ctx, (DWORD64)&digest);
	std::cout << "you entered>>";
	for (int i = 0; i < 20; i++) {
		printf("%02X ", digest[i]);
	}
	printf("\n");

	int c = 0;
	std::cout << "check your pass...\n";
	for (int i = 0; i < 20; i++) {
		c += (digest[i] - (*(BYTE*)((DWORD)&s + i)));
		if (digest[i] != (*(BYTE*)((DWORD)&s + i))) {
			printf("Wrong\n");
			exit(0);
		}
	}
}

void d() {
	__try {
		__asm {
			EM(0xCC)
		}
		std::cout << "debugger detected";
		exit(0);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		e();
	}
}

void c() {
	__try {
		__asm {
			xor eax, eax
			INT 0x2D
			nop
		}
		std::cout << "debugger detected";
		exit(0);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		d();
	}
}

void a() {
	__try {
		EM(0xF1);
		std::cout << "debugger detected";
		exit(0);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		c();
	}
}

void b() {
	std::cout << "Debugger Detected!\n";
	exit(0);
}
int dummyMain() {
	printf("this is Beginning of main func!\n");
	__asm {
		EM(0xEB) __asm call IsDebuggerPresent
		test eax, eax
		jz _a
		call b
		_a :
	}
	if (IsDebuggerPresent()) {
		std::cout << "Debugger Detected!\n";
		exit(0);
	}

	BOOL isD = false;
	__asm {
		mov eax, dword ptr fs : [0x30]
		movzx eax, byte ptr ds : [eax + 0x2]
		mov isD, eax
	}
	DWORD func = (DWORD)b + (!isD) * ((DWORD)a - (DWORD)b);
	__asm call func
	std::string temp2;
	printf("strcmp:=>%I64X\n", st);
	std::cout << "ENTER PASS\n";
	std::cin >> temp2;
	X64Call2(st, 2, (DWORD64)temp2.c_str(), (DWORD64)"\n\0\1");
	temp[0] = 'N';
	temp[1] = 'o';
	temp[2] = '!';
	printf("%s", temp);

	//MessageBoxA(0,"","",0);
	return 0;
}

int main() {
	DWORD64 ntdll64 = GetModuleHandle64(L"ntdll.dll");
	A_SHAFinal = GetProcAddress64(ntdll64, "A_SHAFinal");
	A_SHAInit = GetProcAddress64(ntdll64, "A_SHAInit");
	A_SHAUpdate = GetProcAddress64(ntdll64, "A_SHAUpdate");
	st = GetProcAddress64(ntdll64, "strcmp");
	strcmp2 = GetProcAddress64(ntdll64, "_snprintf");
	dummyMain();
	return 0;
}