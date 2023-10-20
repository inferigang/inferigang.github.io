---
layout: post
title: "The Debug Breaker: Técnica de Anti-Debugging Introdução"
author: astreuzz
image: /assets/banners/tdb.png
description: "Essa é uma série de artigos “TheDebugBreaker” sobre técnicas de anti-debugging aplicadas, nela veremos sobre como debuggers funcionam, métodos de anti-debugging, etc. Essa primeira parte é uma introdução teórica e prática de algumas técnicas."
toc: true
---

# TheDebugBreaker: Técnicas de Anti-Debugging Introdução
# TL;DR

Essa é uma série de artigos “TheDebugBreaker” sobre técnicas de anti-debugging aplicadas, nela veremos sobre como debuggers funcionam, métodos de anti-debugging, etc. Essa primeira parte é uma introdução teórica e prática de algumas técnicas. Por ora não há previsão de quantos artigos essa série terá, mas bastante legal coisa esta por vir, aguardem.

# Introdução

O mundo da cibersegurança evolui a cada dia, com inúmeras vulnerabilidades e mecanismos de proteção surgindo a todo instante. Como dizem por aí, é uma “briga de gato e rato”, onde enquanto um busca proteger, outro busca quebrar um determinado sistema. Essa visão se encaixa perfeitamente em uma área mais específica da segurança, a análise e desenvolvimento de malwares. Isso pois, para que se tenha hoje um meio de detecção para determinado malware, foi um dia necessário fazer uma análise do comportamento e funcionamento do mesmo. Entretanto, assim como antivírus defendem você dos malwares, os malwares precisam se defender dos antivírus, ou melhor, dos analistas que buscarão entender o funcionamento daquele. Mas como um malware é capaz de se “proteger”?

# Mecanismos de Defesa

Como dissertado em [Técnicas de Ofuscação, pt. 1 e 2](https://inferi.zip/paper/tecnicas-de-ofuscacao-em-c-pt-1), uma das formas de um malware esconder suas intenções é através da ofuscação, seja das estruturas que o compõem ou então das informações que esse busca em um sistema. Entretanto, apesar dessa técnica ser relativamente efetiva contra mecanismos de defesa baseados em assinatura, para soluções mais avançadas como EDRs e análises dinâmicas, está longe de ser o suficiente.

## Sobre a Análise Dinâmica

Para que se tenha um profundo entendimento de um malware, geralmente é feito algo que chamamos de análise dinâmica. Nessa técnica, o malware é executado em um ambiente controlado (geralmente uma VM) de uma forma monitorada, ou seja, suas ações são observadas buscando entender o que está acontecendo de fato na máquina. Além disso, é comum o uso de debuggers para que se entenda o malware em nível de código, buscando uma forma de organizar as instruções de máquinas presentes de uma maneira entendível.

# Debuggers

Para aqueles que não conhecem, debuggers são depuradores de códigos, servem basicamente para entender o funcionamento de um determinado programa e buscar por erros de uma forma extremamente poderosa, já que através deles você consegue observar, controlar e modificar o programa em tempo de execução. É através deles, que como mencionado, analistas buscam entender um determinado programa em nível de código, já que possuem recursos poderosos como breakpoints.

## Breakpoints

Os breakpoints são um dos recursos mais poderosos presente nos debuggers, sendo basicamente indicações que um determinado código deve ser pausado em uma determinada instrução. Em geral debuggers fazem essas indicações inserindo um opcode `0xCC` em tempo de execução no programa, quando essa instrução é alcançada, o sistema operacional emite uma exceção de `BREAKPOINT_EXCEPTION`, para que então o controle seja retomado ao debugger através do exception handler e continue a execução após tratada a exceção. Por ora não focaremos no funcionamento interno dos debuggers, mas entender breakpoints até esse ponto é essencial para as técnicas que veremos a seguir.

<img src="/assets/img/tdb0x0-0.png">

Uma demonstração do poder dos breakpoints bypassando uma função básica de anti-debugging:
<img src="/assets/img/no-debugger.gif">

# Anti-Debugging

Então o que é anti-debugging? Bom, para evitar toda essa análise e entendimento de um malware, desenvolvedores criaram formas além da ofuscação para evitar que seus códigos sejam monitorados por debuggers, ou pelo menos tentaram. Essas técnicas chamadas de anti-debugging, consistem geralmente em utilizar de recursos disponíveis no sistema operacional para obter a informação se o binário está sendo monitorado por um debugger ou não. Como vimos em [Técnicas de Ofuscação, pt. 2](https://inferi.zip/paper/tecnicas-de-ofuscacao-em-c-pt-2), o Windows possui uma função chamada `BeingDebugged`, que pode ser utilizada para esse fim, porém hoje adentraremos em técnicas mais avançadas.

Vimos como os breakpoints funcionam, um recurso muito utilizado e importante para os analistas. Mas o que podemos fazer com isso?

## INT 3 (0xCC)

Uma técnica bastante simples de ser entendida e aplicada é a injeção arbitrária do opcode `0xCC` em nosso binário, que como mencionado anteriormente, é utilizado por debuggers para indicar um breakpoint. Isso pode ser feito facilmente através da extensão de inline assembly do MSVC:

<img src="/assets/img/tdb0x0-1.png">

Perceba na imagem acima que, mesmo o breakpoint não sendo definido pelo debugger de fato, ainda sim é interpretado como tal e a execução pausada, dessa forma a exceção `BREAKPOINT_EXCEPTION` é levantada e o ciclo se repete. Mas com apenas isso estamos um pouco limitado, precisamos validar se o breakpoint foi interpretado pelo debugger, mas como?

### MSVC Structured Exception Handling

Através de uma extensão do compilador MSVC chamada Structured Exception Handling (SEH), podemos tratar certas exceções como acessos de memória inválidos, divisões por zero e, a mágica do dia, breakpoints. A sintaxe da SEH é bastante simples:

```c
__try {
	// Bloco a ser executado
} __except(/* Exceção a ser tratada */) {
	// Bloco que trata a exceção
}
```

No nosso caso, no bloco `__try` colocaremos o código com o breakpoint, já em `__except`, indicaremos para tratar a exceção `EXCEPTION_EXECUTE_HANDLER`, que caso seja levantada, nesse caso indicará que não há um debugger (mesmo que seu propósito não seja exatamente esse). Pode parecer meio confuso, mas colocando em ordem, acontece basicamente o seguinte:

1. O programa é executado
2. Caso o debugger encontre o `0xCC` (opcode para breakpoint), a exceção é levantada para o debugger
    1. O debugger trata a exceção e continua a execução, dessa forma o breakpoint é executado e tratado, logo existe um debugger atrelado ao processo e o nosso `__except` não é executado
3. Caso não haja um debugger, o opcode `0xCC` é executado, porém a exceção é levantada para o próprio programa, caindo para ser tratada no bloco do `__except`, indicando então a não presença de um debugger.

Execução sem debugger (`__except` é executado, exceção tratada internamente):

```c
#include <stdio.h>
#include <Windows.h>

int main(void) {
    __try {
        __asm int 3;
        puts("Debugger detected!");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        puts("No debugger detected!");
    }
    return 0;
}
```
<img src="/assets/img/tdb0x0-2.png">

Execução com debugger (`__try` é executado, exceção tratada externamente pelo debugger):

<img src="/assets/img/tdb0x0-3.png">

Outra característica importante sobre o opcode 0xCC (INT 3) é o decremento de EIP e sua versão extendida, os quais veremos em um próximo artigo.

## INT 2DH (0xCD2D)

Além de INT 3, outra instrução que funciona de uma forma semelhante é `INT 2DH` (ou `INT 0x2D`), que também levanta uma exceção `BREAKPOINT_EXCEPTION`, porém incrementa EIP, apontando para a próxima instrução. INT 2DH possui funcionamento interessante pois, com ela podemos escolher arbitrariamente qual exceção tratar ao específica-lá em um bloco de códigos que a levante.

Abaixo um breve exemplo onde é tratada a exceção `EXCEPTION_INT_DIVIDE_BY_ZERO` (levantada `i = i / 0`) ao invés de `BREAKPOINT_EXCEPTION`:

```c
#include <stdio.h>
#include <Windows.h>

int main(void) {
    int i = 1;
    __try {
        __asm int 2dh;
        i = i / 0; // EXCEPTION_INT_DIVIDE_BY_ZERO
        puts("Debugger detected! BREAKPOINT_EXCEPTION");
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (GetExceptionCode() == EXCEPTION_INT_DIVIDE_BY_ZERO) {
            puts("Debugger detected! EXCEPTION_INT_DIVIDE_BY_ZERO");
            exit(1);
        }
        puts("No debugger detected!");
    }
    return 0;
}
```

<img src="/assets/img/tdb0x0-4.png">

# Conclusão

Anti-debugging é com certeza uma área extremamente complexa e gigante, há muito o que aprender e explorar. Conhecer não só o sistema operacional mas o funcionamento de outras aplicações como debuggers é essêncial para técnicas desse tipo, nos próximos artigos comentarei sobre técnicas baseadas em recursos do sistema operacional, como chamdas de API e timing. Entretanto, por hoje é só, espero que tenha entendido e acrescido em seu arsenal de ideias, até a próxima.
