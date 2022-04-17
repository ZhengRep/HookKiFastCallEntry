# Chrome

- IMAGE_THUNK_DATA

```c
typedef struct _IMAGE_THUNK_DATA32 {
union {
PBYTE ForwarderString;
PDWORD Function;
DWORD Ordinal;
PIMAGE_IMPORT_BY_NAME AddressOfData;
} u1;
} IMAGE_THUNK_DATA32;
typedef IMAGE_THUNK_DATA32 * PIMAGE_THUNK_DATA32;
typedef PIMAGE_THUNK_DATA32 PIMAGE_THUNK_DATA;
```

- KiFastCallEntry

```c
2: kd> rdmsr 0x176
msr[176] = 00000000`8483d790

2: kd> u KifastcallEntry
nt!KiFastCallEntry:
8483d790 b923000000      mov     ecx,23h
8483d795 6a30            push    30h
8483d797 0fa1            pop     fs
8483d799 8ed9            mov     ds,cx
8483d79b 8ec1            mov     es,cx
8483d79d 648b0d40000000  mov     ecx,dword ptr fs:[40h]
8483d7a4 8b6104          mov     esp,dword ptr [ecx+4]
8483d7a7 6a23            push    23h
8483d86c 8b3f            mov     edi,dword ptr [edi]
8483d86e 8a0c10          mov     cl,byte ptr [eax+edx]
8483d871 8b1487          mov     edx,dword ptr [edi+eax*4]      //获取到了函数地址

8483d874 2be1            sub     esp,ecx //搜索2be1c1e9
8483d876 c1e902          shr     ecx,2


8483d879 8bfc            mov     edi,esp
```

