---
layout: post
title: Técnicas de Ofuscação em C, pt 2.
author: astreuzz
image: /assets/banners/ofuscacao-c2.png
description: "Técnicas de ofuscação em C, pt 2."
toc: true
---
# Introdução

Esse é o segundo paper da série “Técnicas de Ofuscação em C”, foi visto brevemente na [primeira parte](//inferi.zip/paper/tecnicas-de-ofuscacao-em-c-pt-1) algumas técnicas e recursos da linguagem aplicados na ofuscação. Nesse paper focarei em algumas técnicas de ofuscação em C puro, porém focando na ofuscação de interações com os recursos do sistema Windows.

# Dead Code Insertion

Começando com o mamão com açucar, dead code insertion consiste basicamente numa técnica bastante semelhante com a Dummy Code Insertion, entretanto nessa um código de fluxo é inserido porém nunca executado de fato. A principal diferença desta para a Dummy Code Insertion, pelo menos no exemplos demonstrados anteriormente, é que essa técnica modifica e dificulta não só a leitura do código fonte, mas também insere instruções que serão ativamente observadas no machine code do binário e que, como mencionado, nunca serão executadas (dando sentido ao nome da técnica). Vamos a um exemplo:

```c
#include <stdio.h>
#include <stdlib.h>

volatile int __NoCode;

void __DeadFunction() { exit( -1 ); }

void __MyFunction( int _ ) {
	if ( ( __NoCode = 3301 ) != 1 ) {
		puts("Dead coded!");
	} else {
		__DeadFunction();
	}
}

int main( void ) {
	volatile int __RndName = 0xDEAD;
	if ( ! __RndName ^ 0157255 ) {
		__MyFunction( 0 );
	} else {
		return ~ 0;
	}
}
```

Perceba os nomes estranhos, mas ainda legíveis. Existe outra técnica de ofuscação onde declaramos variáveis e funções com nomes aleatórios e sem significado.

# Shellcoding

Partindo então para uma das minhas técnicas favoritas, a técnica de shellcoding que, apesar de não estritamente ligada a ofuscação, pode ser bastante útil. O termo shellcode deriva de um código usado geralmente para iniciar uma shell, porém com o amplo uso, shellcode passou a consistir basicamente na inserção de um código de máquina hardcoded no código fonte, geralmente a carga útil (payload) de exploits. O que isso significa? É mais simples do que parece, com shellcoding você consegue armazenar o código de funções e ofuscar suas instruções, desofuscando apenas em tempo de execução.

O código a seguir, por exemplo:

```c
#include <stdio.h>
#include <windows.h>
 
int main(){
  MessageBoxA( NULL, "Ad astra!", NULL, 0 );
  return 0;
}
```

Poderia ser facilmente reescrito para:

```c
int main( void ) {
  // MessageBoxA shellcode by RubberDuck
  unsigned char shellcode[]=
  "\xFC\x33\xD2\xB2\x30\x64\xFF\x32\x5A\x8B"
  "\x52\x0C\x8B\x52\x14\x8B\x72\x28\x33\xC9"
  "\xB1\x18\x33\xFF\x33\xC0\xAC\x3C\x61\x7C"
  "\x02\x2C\x20\xC1\xCF\x0D\x03\xF8\xE2\xF0"
  "\x81\xFF\x5B\xBC\x4A\x6A\x8B\x5A\x10\x8B"
  "\x12\x75\xDA\x8B\x53\x3C\x03\xD3\xFF\x72"
  "\x34\x8B\x52\x78\x03\xD3\x8B\x72\x20\x03"
  "\xF3\x33\xC9\x41\xAD\x03\xC3\x81\x38\x47"
  "\x65\x74\x50\x75\xF4\x81\x78\x04\x72\x6F"
  "\x63\x41\x75\xEB\x81\x78\x08\x64\x64\x72"
  "\x65\x75\xE2\x49\x8B\x72\x24\x03\xF3\x66"
  "\x8B\x0C\x4E\x8B\x72\x1C\x03\xF3\x8B\x14"
  "\x8E\x03\xD3\x52\x33\xFF\x57\x68\x61\x72"
  "\x79\x41\x68\x4C\x69\x62\x72\x68\x4C\x6F"
  "\x61\x64\x54\x53\xFF\xD2\x68\x33\x32\x01"
  "\x01\x66\x89\x7C\x24\x02\x68\x75\x73\x65"
  "\x72\x54\xFF\xD0\x68\x6F\x78\x41\x01\x8B"
  "\xDF\x88\x5C\x24\x03\x68\x61\x67\x65\x42"
  "\x68\x4D\x65\x73\x73\x54\x50\xFF\x54\x24"
  "\x2C\x57\x68\x4F\x5F\x6F\x21\x8B\xDC\x57"
  "\x53\x53\x57\xFF\xD0\x68\x65\x73\x73\x01"
  "\x8B\xDF\x88\x5C\x24\x03\x68\x50\x72\x6F"
  "\x63\x68\x45\x78\x69\x74\x54\xFF\x74\x24"
  "\x40\xFF\x54\x24\x40\x57\xFF\xD0";

  ( (void ( * )() )shellcode )();

  return 0;
}
```

## Contrapontos

Mundo afora existem diversas ferramentas para criação de shellcode e, apesar de serem bastante práticas como o próprio msfvenom do metasploit, estão repletos de assinaturas, logo sua detecção em geral é bastante simples e rápida. Para quem deseja utilizar esses shellcodes, recomendo a aplicação de técnicas como XOR encoding, mencionada na primeira parte, para dificultar a detecção baseada em assinatura.

# Anti-Debugging

Uma das formas de impedir o entendimento de um software é através de técnicas de anti-debugging, já que dessa forma, é criada uma forma de evitar ler o comportamento do programa em tempo de execução. Essa é uma técnica que em geral é muito mais eficiente quando encadeada com as técnicas anteriores. Em C, técnicas como essas estão presentes em diversos malwares e, uma das formas mais básicas de se aplicar é utilizando de algumas informações sobre o processo, em especial, no Windows, um atributo chamado BeingDebugged.

## BeingDebugged

BeingDebugged é um atributo que é armazenado na PEB (Process Environment Block) do processo, essa é uma estrutura que armazena diversas informações acerca do processo em execução, como o endereço do binário executável, parâmetros do processo, etc. Por hoje não nos atentaremos tanto aos detalhes dessa estrutura, mas caso queira consultar o valor do atributo BeingDebugged, existe uma função chamada `IsDebuggerPresent()` na WinAPI:

```c
#include <stdio.h>
#include <windows.h>

int main( void ) {

  if( IsDebuggerPresent() ) {
    puts( "No debugger allowed" );
    while( 1 ); // Pause
    return 1;
  }

  // Obfuscated code here
  puts( "Ad astra!" );
  while( 1 );	

  return 0;
}
```

### BeingDebugged sem chamadas de APIs

Na parte 3 (em desenvolvimento) veremos que uma das formas de analistas entenderem o funcionamento de um programa é observando as APIs importadas, que podem ser obtidas através da IAT:

![1.png](/assets/img/o1.png)

Analisando os symbols em tempo de execução, é fácil observar o uso da função mencionada:

![2.png](/assets/img/o2.png)

Para evitarmos isso, sabendo o funcionamento da função `IsDebuggerPresent()` podemos obter o valor do atributo `BeingDebugged` apenas usando algumas linhas de inline assembly:

```c
#include <stdio.h>

int main( void ) {
  unsigned char r;

  __asm__(
    ".intel_syntax noprefix\n\t"
    "mov eax, dword ptr fs:[0x30]\n\t" // PEB located at 0x30 in TEB
    "mov eax, [eax + 0x2]\n\t" // BeingDebugged flag
    "mov %0, al\n\t"
    ".att_syntax prefix"
    : "=r" (r)
  );

  if( r ) {
    puts( "No debugger allowed" );
    while( 1 );
    return 1;
  }

  // Obfuscated code here
  puts( "Fuck WinAPI!" );
  while( 1 );

  return 0;
}
```

Com isso, apesar da DLL kernel32 ainda ser exposta, nela não será mais mostrado o uso da função IsBeingDebugged!

![Untitled](/assets/img/o4.png)

## Bypassando BeingDebugged

Hoje em dia debuggers são bastante complexos e possuem técnicas para bypassar essa validação, x64dbg por exemplo, possui a opção de escondê-lo:

![Untitled](/assets/img/o3.png)

# Conclusão

Por hoje vimos que, como dito na primeira parte, para uma boa ofuscação faz-se necessário não só o uso de recursos da linguagem mas do sistema operacional como um todo. Entender as estruturas essênciais e seu funcionamento o ajudará no processo de ofuscação. Espero que tenha expandido seu arsenal de ideias, até a próxima!

#InferiGang2Years

⠀⠀⠀⢰⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠘⡇⠀⠀⠀⢠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢷⠀⢠⢣⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢘⣷⢸⣾⣇⣶⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣿⣿⣿⣹⣿⣿⣷⣿⣆⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢼⡇⣿⣿⣶⣯⣭⣷⣶⣿⣿⣶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠸⠣⢿⣿⣿⣿⣿⡿⣛⣭⣭⣭⡙⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⠿⠿⠿⢯⡛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣾⣿⡿⡷⢿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⡔⣺⣿⣿⣽⡿⣿⣿⣿⣟⡳⠦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⣭⣾⣿⠃⣿⡇⣿⣿⡷⢾⣭⡓⠀⠀⠀⠀⠀- Hacking et Ultra⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣾⣿⡿⠷⣿⣿⡇⣿⣿⣟⣻⠶⣭⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣋⣵⣞⣭⣮⢿⣧⣝⣛⡛⠿⢿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣀⣀⣠⣶⣿⣿⣿⣿⡿⠟⣼⣿⡿⣟⣿⡇⠀⠙⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⡼⣿⣿⣿⢟⣿⣿⣿⣷⡿⠿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠉⠁⠀⢉⣭⣭⣽⣯⣿⣿⢿⣫⣮⣅⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣿⣟⣽⣿⣿⣿⣿⣾⣿⣿⣯⡛⠻⢷⣶⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⡞⣾⣿⣿⣿⣿⡟⣿⣿⣽⣿⣿⡿⠀⠀⠀⠈⠙⠛⠿⣶⣤⣄⡀⠀⠀
⠀⠀⠀⣾⣸⣿⣿⣷⣿⣿⢧⣿⣿⣿⣿⣿⣷⠁⠀⠀⠀⠀⠀⠀⠀⠈⠙⠻⢷⣦
⠀⠀⠀⡿⣛⣛⣛⣛⣿⣿⣸⣿⣿⣿⣻⣿⣿⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢸⡇⣿⣿⣿⣿⣿⡏⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢰⣶⣶⣶⣾⣿⢃⣿⣿⣿⣿⣯⣿⣭⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
