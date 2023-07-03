---
layout: post
title: Técnicas de Ofuscação em C, pt 1.
author: astreuzz
image: /assets/banners/tecnicas-de-ofuscacao-em-c.png
description: "Uma introdução sobre técnicas de ofuscação em C"
toc: true
---

# Introdução

A linguagem C é com toda certeza uma das mais amadas hoje e, sejamos sinceros, não faltam motivos para isso. Quando tratamos de desenvolvimento de malwares, C é uma das primeiras linguagens a vir na mente, isso devido a sua portabilidade e funcionalidades dispostas como o acesso a recursos do sistema operacional e baixo nível. Tratando de malwares, a furtividade é imprescindível e, para isso, uma das técnicas mais utilizadas e conhecidas é a ofuscação de códigos. Nesse paper, abordo algumas técnicas de ofuscação usadas em C.

# O que é Ofuscação

De início, é importante termos em mente o que é ofuscação, um termo que você deve ouvir bastante no mundo da computação, principalmente no desenvolvimento e análise de malwares. Ofuscar significa basicamente esconder, tornar de difícil entendimento. Tratando novamente de malwares, ofuscar significa, em essência, esconder a intenção de um determinado código, seja para evadir sistemas de defesa como antivirus e EDRs ou dificultar a vida de analistas de malwares. Vamos a um exemplo prático:

Em um cenário hipotético, digamos que um antivirus bloqueia a função `puts()` da biblioteca `stdio.h` da libc, finalizando imediatamente todo processo que a executa, qual o esperado para o seguinte código? Dando nome aos bois, ao longo do artigo esse primeiro código será algumas vezes referenciado como `dumb.c`:

```c
#include <stdio.h>

int main( void ) {
	puts( "Scientia Potentia Est!" );
	return 0;
}
```

É claro, nesse cenário, o processo seria bloqueado e finalizado. Entretanto, estudando sobre o funcionamento da função puts, percebemos um funcionamento bastante simples e fácil de implementar. Poderiamos usar, por exemplo, a função putchar em um loop e contornar a regra desse cenário:

```c
#include <stdio.h>

int main( void ) {
	char *s = "Scientia Potentia Est!\n";
	do {
		putchar( *s );
	} while( *s++ != '\0' );

	return 0;
}
```

Essa é a primeira e talvez a mais simples técnica de ofuscação que abordarei, chamada *Instruction Pattern Transformation*.

# Instruction Pattern Transformation

Esse é o nome dado a técnica vista anteriormente, consiste basicamente na utilização de diferentes instruções para efetuar uma mesma tarefa, no exemplo dado, usamos a função putchar para obter o mesmo resultado a função puts. Claro, esse é um exemplo simples onde facilmente se pode deduzir o comportamento do programa, porém é importante ressaltar que em um programa ofuscado geralmente faz-se uso de diversas técnicas, seja de forma encadeada ou isolada. Vamos complicar mais o exemplo anterior:

```c
#include <stdio.h>
int main( void ) {
  int idx = 0;
  do {
        putchar( (char *[]){ "Scientia Potentia Est!\n" }[ 0 ][ idx++ ] );
  } while( *( (char *[]){ "abcdefghijklmnopqrstuvw" }[ 0 ] + idx ) != '\0' );
	
	return 0;
}
```

Um pouco mais confuso, não é? Apesar disso, continua basicamente o mesmo comportamento do primeiro `dumb.c`, exceto é claro pela inserção de diferentes recursos. No exemplo acima, é usado alguns recursos da linguagem C, principalmente a aritimética de ponteiros.

## Um Pouco sobre Strings

Para que se entenda o exemplo acima é necessário uma pausa e relembrar sobre strings e ponteiros. Como sabemos, em C não existe um tipo especial para strings, dizemos que uma string é uma array de caracteres terminada em null byte. Os identificadores de arrays por sua vez, podem decair para ponteiros dependendo da ocasião, por exemplo em expressões, e é basicamente com isso que construimos o código. Um exemplo de *array-to-pointer* decay:

```c
#include <stdio.h>

int main( void ) {
	char *s = "inferi\0gang";
	puts(s);
	puts(s + 7); // Array-to-pointer decay
}
```

No exemplo acima temos a string `inferi\0gang` armazenada em um `char *` (char pointer), onde duas strings são impressas no terminal: `inferi` e `gang` de forma separada com a função `puts()`. Talvez você deve esta pensando: “Que C#!$LHOS é isso? Como assim?”

A string `inferi` é impressa e finaliza no primeiro null byte `\0` e a segunda finaliza no null byte declarado implicitamente pelo compilador no string literal. O primeiro `puts(s)` nada nos interessa, entretanto o segundo `puts(s + 7)` possui um comportamento interessante. Nele acontece o decaimento de array em ponteiro, onde `s` aponta não para uma array, mas agora para o primeiro elemento da array. Dessa forma, ao incrementar podemos acessar os outros elementos dessa array, já que são armazenados de forma sequencial.

## Compound Literals

Outro recurso utilizado e não tanto conhecido foi compound literals. Esse recurso permite instanciarmos objetos anônimos, ou seja, sem identificadores diretamente em um bloco de código. Esse comportamento poderia ser facilmente obtido com um string literal, porém como parte da técnica, vemos diferentes formas de se obter um mesmo resultado.

`(char *[]){ "Scientia Potentia Est!\n" }[0]` 

Aqui instanciamos um compound literal para um ponteiros de array de chars. em seguida acessamos o primeiro índice que armazena a string `"Scientia Potentia Est!\n"`

Voltando ao exemplo, ainda temos um inteiro `i` que é incrementado, mas a partir de agora ficou fácil entender, né?

1. `(char *[]){ "Scientia Potentia Est!\n" }[ 0 ][ idx++ ]` Aqui acessamos cara elemento da string armazenada no compound literal

2. `*( (char *[]){ "abcdefghijklmnopqrstuvw" }[ 0 ] + idx` Aqui somamos `i` em uma máscara que contém exatamente 23 elementos (o mesmo tamanho da string que será impressa no terminal). É apenas uma forma de acrescentar `idx`, poderiamos obter o mesmo resultado com `idx != 23`

# String Obfuscation

Como vimos, strings são um ótimo lugar para aplicarmos os recurso da linguagem, inclusive são um dos principais meios de detecção dos sistemas de defesa. É por isso que, apesar das técnicas mencionadas serem relativamente boas, nem sempre serão eficientes isoladamente e um problema dos códigos anteriores é o armazenamento das strings. 

## .rodata e Stack

Numa definição de um char pointer como a seguinte: `char *s = "inferigang"` temos um ponteiro para um char armazenado no binário, numa área de apenas leitura chamada `.rodata`. Essa string poderia ser facilmente obtida com uma análise simples, um um exemplo com o utilitário `strings` do GNU:

![ofus-0.png](/assets/img/ofus-0.png)

Isso poderia facilmente ser resolvido usando uma array de chars: `char s[] = "inferigang"` que, diferentemente de um char pointer, é armazenada na stack. Entretanto, ainda teriamos um problema explicado na imagem a seguir:

![ofus-1.png](/assets/img/ofus-1.png)

Sim, ainda assim a string pode ser facilmente identificada mesmo estando na stack.

## XOR

Para melhorar essa abordagem, podemos aplicar uma outra técnica de ofuscação chamada XOR encrypt, a qual consiste basicamente em aplicar uma operação XOR bitwise nos valores ASCII usando uma máscara como “senha”. A implementação de XOR encrypt é bastante simples, um breve exemplo:

![ofus-2.png](/assets/img/ofus-2.png)

# Dummy Code Insertion

Outra técnica bastante simples e comum é a inserção de código dummy no programa. Um código dummy é algo que não modifica o comportamento do programa, com o propósito de gerar uma assinatura diferente ou dificultar a vida de um analista de malware. Exemplo:

```c
#include <stdio.h>

int main( void ) {
  int _dummyC0de = 0xdead;
  char *s = "RandomSTRINGreadONLY";
	puts( "Scientia Potentia Est!" );
  _dummyC0de ? "ANOTHERSTRING" : "DUMB";
  dummy:
    "MYSTRING";
	return 0;
}
```

# Conclusão

Ofuscação consiste numa arte que requer não só conhecimento amplo sobre o funcionamento do computador, mas da linguagem. Hoje vimos algumas breves técnicas de ofuscação alinhadas com o conhecimento sobre a linguagem de programação C, logicamente existem diversas outras técnicas e recursos a serem utilizados para este fim, entretanto por hoje esta primeira parte chega ao fim. Espero que tenha acrescentado algo em seu arsenal, persevera ad inferi!
