---
layout: post
title: DLL Injection na Prática
author: spyware
author_url: 
image: /assets/banners/dlli.png
description: "Um pouco sobre DLL na prática"
toc: true
---

**DLL (Dynamic Link Library)**, como o próprio nome já diz, é uma biblioteca contendo dados e códigos que vários aplicativos podem utilizar ao mesmo tempo. Através da modularização, reutilização de código, uso eficiente de memória e espaço em disco reduzido, seus usos vão desde a execução de funcionalidades do sistema operacional até se tornarem dependências de aplicações de terceiros.

O próprio sistema Windows fornece proteção para com essas DLLs, através do Windows File Protection, protegendo DLLs de serem apagadas ou alteradas por alguém não autorizado, portanto, quando há alguma tentativa de alteração em uma DLL marcada como system DLL, o [Windows File Protection](https://learn.microsoft.com/en-us/troubleshoot/windows-client/deployment/dynamic-link-library#dll-dependencies) bloqueia essa tentativa procurando por assinaturas digitais válidas.

Temos duas formas de carregarmos DLLs em uma aplicação, sendo elas: Load-time dynamic linking e Run-time dynamic linking.

## Load-time dynamic linking:
A aplicação inclui DLLs no seu código estaticamente, ou seja, inclui um arquivo header (.h) e importa esse arquivo header no momento de sua compilação. Deixando com que o Linker faça o trabalho de carregar e resolver a DLL e suas respectivas funções.

## Run-time dynamic linking:
A aplicação utiliza das funções LoadLibrary/Ex em conjunto da GetProcAddress para obter o endereço da função de uma DLL enquanto em Runtime.

Já entendemos o que é uma DLL, e como as mesmas são utilizadas, agora podemos entender a técnica de injeção de código: DLL Injection (T1055.001 — [https://attack.mitre.org/techniques/T1055/001/](url)).

**DLL Injection** é uma técnica utilizada por malwares para executar um código malicioso no contexto de um processo **legítimo** do sistema. Por meio da injeção de uma DLL em um processo que já está **em Runtime**, o malware consegue o mesmo nível de acesso e privilégio do processo comprometido.

> _(Em muitos casos, o malware cria um processo mascarado (T1036 —[ https://attack.mitre.org/techniques/T1036/](url)) e injeta a DLL nesse processo; Podendo até mesmo realizar uma injeção em si próprio para evadir detecções)_

Sua contaminação se dá através do carregamento dessa DLL maliciosa na memória de um processo, podendo: ou chamar uma **função exportada** da DLL injetada (com o código malicioso) ou executar o código malicioso contido no [DllMain](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain). Essas etapas todas ocorrem dentro do contexto do processo legítimo comprometido.

<img src="https://miro.medium.com/v2/resize:fit:1100/format:webp/1*vR5MuwbWNqj1luLou_i63g.jpeg">

Agora vamos nos aprofundar um pouco mais nessas etapas. Uma DLL Injection é performada através da escrita do **path** para a DLL maliciosa dentro do [Virtual Address Space](https://learn.microsoft.com/en-us/windows/win32/memory/virtual-address-space) do processo alvo antes de carregar a DLL maliciosa, invocando uma nova thread.

Essa escrita pode ser feita através das funções `OpenProcess`, `VirtualAlloc/Ex` e `WriteProcessMemory`, só então invocada com a `CreateRemoteThread`, que por sua vez, chama a `LoadLibrary` e carrega a DLL maliciosa.

Então temos o seguinte workflow:

```c
OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread
```

- **OpenProcess**:
Abre um objeto de processo local existente. Recebendo como argumentos o o tipo de acesso ao processo (Geralmente **PROCESS_ALL_ACCESS**), um booleano para determinar se os processos criados pelo processo acessado herdarão seu handle; e o PID do processo a ser aberto. Retorna um handle para o processo especificado.

```c
processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, [PID]);
```

- **VirtualAllocEx**:
Utilizada para reservar, confirmar ou alterar o estado do virtual address space de um processo, podendo ele ser local ou **remoto (Ex)**. Recebe como parâmetros o handle para um processo (**retorno da OpenProcess**), o tamanho da memória a ser alocada, o tipo de alocação de memória (Geralmente **MEM_COMMIT**) e o tipo de proteção para a região da memória recém alocada. Retornando o endereço da memória alocada.

```c
remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof(malicious_dll), MEM_COMMIT, PAGE_READWRITE);
```

- **WriteProcessMemory**:
Escreve dados dentro da memória de um processo. Recebendo como parâmetros o **handle** para o processo a ser escrito, um ponteiro para o endereço de memória a ser escrito (**retorno da VirtualAllocEx**), um ponteiro para o buffer contendo os dados a serem escritos e o número de bytes a serem escritos. Retornando um valor não-zero para sucesso.

```c
WriteProcessMemory(processHandle, remoteBuffer, (LPVOID)malicious_dll, sizeof(malicious_dll), NULL);
```

- **CreateRemoteThread**:
Cria uma thread que roda no virtual address space de outro processo. Recebe como parâmetros um handle para em que a thread será criada (**retorno da OpenProcess**), um ponteiro para a estrutura [SECURITY_ATRIBUTES](https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ns-wtypesbase-security_attributes) (especifica um security descriptor para a nova thread e determina se o child process podem herdar o handle retornado), o tamanho inicial da stack em bytes, o endereço em que a thread deve ser iniciada (**lpStartAddress** — Argumento **importantíssimo** na hora de extrair um binário malicioso fruto de uma injeção de código), um ponteiro para a variável a ser atribuída a função da thread, uma flag que controla a criação da thread (**Geralmente sendo 0 — a thread é executada imediatamente após sua criação**) e um ponteiro para a variável que recebe o identificador da thread. Retornando um handle para a thread criada.

```c
CreateRemoteThread(processHandle, NULL, 0, lpStart, remoteBuffer, 0, NULL);
```

E assim temos nossa DLL maliciosa sendo executada no contexto de outro processo.

# Detecção

Agora falando da detecção dessa técnica, temos maneiras bem sólidas e simples, podemos por exemplo:

- Monitorar a chamada das APIs citadas anteriormente.
- Procurar por processos carregando arquivos que acabaram de ser criados (janela de tempo de 1 minuto).
- Procurar por DLLs suspeitas.
- Procurar por inconsistências na memória de um processo, comparando-o com uma cópia do processo legítimo

YARA:

```
import "pe"

rule DllInjection {
   meta:
     description = "Rule to detect Dll Injection in general"
   strings:
     $load_01 = "LoadLibraryA"
     $remote_01 = "NtCreateThreadEx"
   condition:
     uint16(0) == 0x5a4d and
     pe.imports("kernel32.dll", "OpenProcess") and/or
     pe.imports("kernel32.dll", "VirtualAllocEx") and
     pe.imports("kernel32.dll","WriteProcessMemory") and/or
     pe.imports("kernel32.dll", "LoadLibrary") and
     pe.imports("kernel32.dll", "GetProcAddress") and
     pe.imports("kernel32.dll","CreateRemoteThread") and/or
     all of them
}
```

Essa foi uma breve introdução e explicação sobre Dll Injection, espero que tenham gostado. Uma ótima noite : )
