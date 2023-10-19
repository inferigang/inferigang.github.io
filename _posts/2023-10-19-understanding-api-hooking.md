---
layout: post
title: Understanding API Hooking
author: sorahed
image: /assets/banners/api-hooking.png
description: "Uma visão introdutória sobre o que é, como funciona e aplicações práticas da técnica de API Hooking utilizada em soluções de defesas como AV/EDR."
toc: true
---

# Understanding API Hooking

Uma das principais formas de detecção de malware em runtime utilizada por AV’s e EDR’s, é a chamada técnica de API Hooking, neste artigo vou introduzir bem levianamente sobre esse conceito, como funciona e como é aplicado (não parta da premissa que hooks só podem ser implementados dessa forma, no artigo vou demonstrar só uma das maneiras de realizar essa ação, existes diversas outras, boa leitura 🤗).

## API Hooking

API Hooking é uma técnica utilizada para interceptar e modificar o comportamento da função de uma api. O hooking envolve a substituição da implementação original da função da api por uma versão personalizada que por sua vez, executa algumas ações adicionais antes ou depois de chamar a função original. Isso permite modificar o comportamento de um programa sem modificar seu código-fonte.

## Ways to hook

Uma das maneiras mais clássicas de implementar API Hooking é feita por meio dos chamados *trampolines.* Um trampoline é um shellcode utilizado para alterar o caminho de execução do código, saltando para outro endereço específico dentro do espaço de endereço de um processo. O shellcode do trampoline é inserido no início da função, fazendo com que a função seja hookada. Quando a função hookada é chamada, o shellcode do trampoline é acionado, e o fluxo de execução é passado e alterado para outro endereço, resultando na execução de uma função diferente.

Além dos trampolines, temos outra abordagem para realizar API Hooking, que se chama Inline Hooking, esse método opera de forma semelhante aos hooks feitos com trampolines. A diferença está no fato de que os inline hooks retornam a execução para a função legítima, permitindo assim que a execução normal continue. Esse tipo de abordagem para hook são mais difíceis de implementar e acabam sendo difíceis de manter, porém ainda sim os inline hooks são mais eficientes.

Neste artigo utilizaremos de uma biblioteca chamada [Detours](https://github.com/microsoft/Detours), para realizar os hooks.

## Detours Library

[Detours Hooking Library](https://github.com/microsoft/Detours) é uma biblioteca desenvolvida pela Microsoft, que permite interceptar e redirecionar chamadas de funções do Windows. A biblioteca redireciona chamadas de funções específicas para uma função de substituição definida pelo usuário que pode executar tarefas adicionas ou modificar o comportamento da função original.

## The Transactions

A biblioteca Detours substitui as primeiras instruções da função de destino, que é a função a ser hookada, por um “salto incondicional”(comumente conhecido como unconditional jump) para a função de desvio fornecida pelo usuário, que a é a função a ser executada. Esse salto incondicional é conhecido como o trampoline que vimos acima.

Essa biblioteca então utiliza de “transações” para instalar e remover os hooks de uma função específica. Ao usar transações, uma nova transação pode ser iniciada, os hooks de função podem ser adicionados e, em seguida, confirmados. Ao confirmar a transação, todos os hooks de função adicionados à transação serão aplicados ao programa.

## ****Using The Detours Library****

Para usar as funções da biblioteca Detours, o repositório Detours deve ser baixado e compilado para obter os arquivos de biblioteca estática (.lib) necessários para a compilação. Além disso, o header  [detours.h](https://github.com/microsoft/Detours/blob/main/src/detours.h) deve ser incluído, o que é explicado no wiki do Detours na seção [Usando o Detours](https://github.com/microsoft/Detours/wiki/Using-Detours).

Para obter ajuda adicional para adicionar arquivos .lib a um projeto, consulte a [documentação da Microsoft.](https://learn.microsoft.com/en-us/cpp/build/reference/dot-lib-files-as-linker-input?view=msvc-170)

## Detours API Functions

Ao usar qualquer método de hook, a primeira etapa é sempre retornar o endereço da função WinAPI a ser hookada. O endereço da função é necessário para determinar onde as instruções de jump serão colocadas. Neste artigo, a função VirtualAllocEx será utilizada como uma função para hook.

Abaixo estão as funções da API que a biblioteca Detours oferece:

- [DetourTransactionBegin](https://github.com/microsoft/Detours/wiki/DetourTransactionBegin) - Inicia uma nova transação para anexar ou desanexar detours. Essa função deve ser chamada primeiro ao fazer hook e unhooking.
- [DetourUpdateThread](https://github.com/microsoft/Detours/wiki/DetourUpdateThread) - Atualiza a transação atual. É usado pela biblioteca Detours para alistar um thread na transação atual.
- [DetourAttach](https://github.com/microsoft/Detours/wiki/DetourAttach) - Instala o hook na função de destino em uma transação atual. Isso não será confirmado até que DetourTransactionCommit seja chamado.
- [DetourDetach](https://github.com/microsoft/Detours/wiki/DetourDetach) - Remove o hook da função visada em uma transação atual. Isso não será confirmado até que DetourTransactionCommit seja chamado.
- [DetourTransactionCommit](https://github.com/microsoft/Detours/wiki/DetourTransactionCommit) - Confirma a transação atual para anexar ou desanexar detours.

As funções acima retornam um valor LONG que é usado para entender o resultado da execução da função. Uma API Detours retornará NO_ERROR, que é um 0, se for bem-sucedida e um valor diferente de zero em caso de falha. O valor diferente de zero pode ser usado como um código de erro para fins de debug.

## Permuting a hooked API

A próxima etapa é criar uma função para substituir a API hookada. A função de substituição deve ter o mesmo tipo de dado, e opicionalmente receber os mesmos parâmetros. Isso permite a inspeção ou modificação dos valores dos parâmetros. Por exemplo, a função a seguir pode ser usada como uma função de detours para VirtualAllocEx.

Vamos salvar um ponteiro para a função original antes de hooka-la. Esse ponteiro pode ser armazenado em uma variável global e invocado em vez da função hookada dentro da função detours.

```cpp
//pointer to VirtualAllocEx
LPVOID (WINAPI* pVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = VirtualAllocEx;

int HookVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect){
	printf("[!] Allocate Remote memory? Today not ... \n");
	
	return IDOK;
}
```

## Making it happen

Conforme explicado anteriormente a biblioteca Detours, funciona usando transações.
Portando, para hookar uma função da API, é necessário criar uma transação, enviar uma ação(hooking ou unhooking) para a transação e, em seguida, confirmar a transação. O código abaixo executa essas etapas.

```cpp
//pointer to VirtualAllocEx
LPVOID (WINAPI* pVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = VirtualAllocEx;

int HookVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect){
	printf("[!] Allocate Remote memory? Today not ... \n");
	
	return IDOK;
}

// Set hooks on VirtualAllocEx
BOOL Hook(void) {

    DWORD dwDetoursErr = NULL;

	if ((dwDetoursErr = DetourTransactionBegin()) != NO_ERROR){
		printf("[!] DetourTransactionBegin Failed With Error: %d \n", dwDetoursErr);
		return false;
	}

	if ((dwDetoursErr = DetourUpdateThread(GetCurrentThread())) != NO_ERROR) {
		printf("[!] DetourUpdateThread Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}

	if ((dwDetoursErr = DetourAttach(&(PVOID&)pVirtualAllocEx, HookVirtualAllocEx)) != NO_ERROR) {
		printf("[!] DetourAttach Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}

	if ((dwDetoursErr = DetourTransactionCommit()) != NO_ERROR) {
		printf("[!] DetourTransactionCommit Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}
	printf("[!] VirtualAllocEx() hooked! (res = %d)\n", dwDetoursErr);
	
	return TRUE;
}
```

## Unhooking

```cpp
// Revert all changes to original code
BOOL UnHook(void) {
	
	DWORD dwDetoursErr = NULL;

	if ((dwDetoursErr = DetourTransactionBegin()) != NO_ERROR){
		printf("[!] DetourTransactionBegin Failed With Error: %d \n", dwDetoursErr);
		return false;
	}

	if ((dwDetoursErr = DetourUpdateThread(GetCurrentThread())) != NO_ERROR) {
		printf("[!] DetourUpdateThread Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}

	if ((dwDetoursErr = DetourDetach(&(PVOID&)pVirtualAllocEx, HookVirtualAllocEx)) != NO_ERROR) {
		printf("[!] DetourAttach Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}

	if ((dwDetoursErr = DetourTransactionCommit()) != NO_ERROR) {
		printf("[!] DetourTransactionCommit Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}

	printf("[!] Hook removed from VirtualAllocEx With Result = %d\n", dwDetoursErr);
	
	return TRUE;
}
```

Agora que já temos nossas funções para realizar o hook e o unhooking da função, podemos testar, eu vou compilar este código em forma de DLL, para demonstrar mais ou menos na prática como um EDR faz, que é o chamado Userland Hooking, que basicamente ele injeta uma DLL no processo e essa DLL monitora essas chamadas.

## Main Code

```cpp
#include <stdio.h>
#include <windows.h>
#include "detours.h"
#pragma comment(lib, "user32.lib")

BOOL Hook(void);
BOOL UnHook(void);

//pointer to VirtualAllocEx
LPVOID (WINAPI* pVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = VirtualAllocEx;

int HookVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect){
	printf("[!] Allocate Remote memory? Today not ... \n");
	
	return IDOK;
}

// Set hooks on VirtualAllocEx
BOOL Hook(void) {

    DWORD dwDetoursErr = NULL;

	if ((dwDetoursErr = DetourTransactionBegin()) != NO_ERROR){
		printf("[!] DetourTransactionBegin Failed With Error: %d \n", dwDetoursErr);
		return false;
	}

	if ((dwDetoursErr = DetourUpdateThread(GetCurrentThread())) != NO_ERROR) {
		printf("[!] DetourUpdateThread Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}

	if ((dwDetoursErr = DetourAttach(&(PVOID&)pVirtualAllocEx, HookVirtualAllocEx)) != NO_ERROR) {
		printf("[!] DetourAttach Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}

	if ((dwDetoursErr = DetourTransactionCommit()) != NO_ERROR) {
		printf("[!] DetourTransactionCommit Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}
	printf("\n[!] VirtualAllocEx hooked With Result : %d\n", dwDetoursErr);
	
	return TRUE;
}

// Revert all changes to original code
BOOL UnHook(void) {
	
	DWORD dwDetoursErr = NULL;

	if ((dwDetoursErr = DetourTransactionBegin()) != NO_ERROR){
		printf("[!] DetourTransactionBegin Failed With Error: %d \n", dwDetoursErr);
		return false;
	}

	if ((dwDetoursErr = DetourUpdateThread(GetCurrentThread())) != NO_ERROR) {
		printf("[!] DetourUpdateThread Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}

	if ((dwDetoursErr = DetourDetach(&(PVOID&)pVirtualAllocEx, HookVirtualAllocEx)) != NO_ERROR) {
		printf("[!] DetourAttach Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}

	if ((dwDetoursErr = DetourTransactionCommit()) != NO_ERROR) {
		printf("[!] DetourTransactionCommit Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}

	printf("[!] Hook removed from VirtualAllocEx With Result = %d\n", dwDetoursErr);
	
	return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {

    switch (dwReason)  {
		case DLL_PROCESS_ATTACH:
			Hook();
			break;
			
		case DLL_THREAD_ATTACH:
			break;
			
		case DLL_THREAD_DETACH:
			break;
			
		case DLL_PROCESS_DETACH:
			UnHook();
			break;
	}
	
    return TRUE;
}
```

Já com a DLL compilada, vou utilizar um código para injection simples que nada mais faz do que injetar alguns opcodes em um processo remoto, mas oque queremos aqui é realmente saber se o hook foi feito na função de destino, nesse programa irá conter a função que queremos hookar.

```cpp
pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	if(pRemoteCode == NULL){
		printf("[!] VirtualAllocEx Failed With Error : (%d) \n", GetLastError());
		return -1;
	}
	
	if(!WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL)){
		printf("[!] WriteProcessMemory Failed With Error: (%d) \n", GetLastError());
		return -1;
	}
	
	hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE) pRemoteCode, NULL, 0, NULL);
	if (hThread != NULL) {
			WaitForSingleObject(hThread, 500);
			CloseHandle(hThread);
			return 0;
	}
	return -1;
}
```

Eu vou utilizar o ProcessHacker para injetar a DLL no processo de destino, mas antes vou rodar o programa normalmente, sem injetar a DLL.

<img src="/assets/img/Detouring (2).png">


O programa rodou normalmente, e alocou a memória sem nenhum tipo de erro. Agora enquanto o processo roda, e esta suspenso por um getchar, eu vou injetar a DLL no processo, e vamos ver oque acontece.
<img src="/assets/img/Detouring (1).png">


<img src="/assets/img/Detouring (3).png">

E voilà, o hook foi triggado com sucesso e o processo terminou antes de alocar a memória, muito top não é?

## Conclusion

Vimos neste artigo uma breve introdução sobre oque são os hooks, como funcionam e como são inseridos nos programas, para você leitor que irá práticar, recomendo que ao decorrer dos testes você utilize um debbuger para visualizar melhor o hook sendo adicionado e também removido.

## References

[Detours Library Code](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwjNjMfB4oKCAxUYkpUCHYnOCCwQFnoECBcQAQ&url=https%3A%2F%2Fgithub.com%2Fmicrosoft%2FDetours&usg=AOvVaw0G-BNhaMdZj9MwgRNtcYJA&opi=89978449)

[Include Detours In VS](https://stackoverflow.com/questions/67463804/how-to-include-microsoft-detours-library-in-visual-studio)

[Detours Wiki](https://github.com/microsoft/Detours/wiki/Using-Detours)
