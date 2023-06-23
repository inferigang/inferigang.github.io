---
layout: post
title:  "Hiding System Calls Using Ordinals in C#"
author: sorahed
author_url: //twitter.com/unkvolism
description: "A little bit about how to use ordinals to hide system calls in C#"
image: /assets/img/hiding-system-calls-with-ordinals-in-c#.png
categories: c# windows 
---


# Using ordinals in C# to hide function calls

É muito comum na area de redteam, ao fazer um teste de intrusão a uma rede interna, nos depararmos com soluções de anti-virus, as quais cada dia são investidos milhões de dólares para aprimorar suas táticas de detecção.

Sabendo disso atacantes, também buscam sempre por novas táticas para evadir essas soluções como EDR/XDR e anti-virus no geral.

E como uma breve introdução a esse tema de evasion, vou apresentar a vocês uma coisa muito legal, que pode ser feita para “obfuscar” a chamada direta de funções no seu código.

A técnica que vou estar mostrando hoje, é muito interessante pois ela não é muito bem documentada, e também é facil de ser executada, e funciona muito bem contra os anti-virus.

## Vamos lá !!!

Primeiramente temos aqui, um código comum em C#.

Este código basicamente exibe uma messageBox, utilizando a dll “user32.dll” do windows.
Dentro dessa dll, se encontra a função que vamos utilizar, que é a messageBox.

```csharp
using System;
using System.Runtime.InteropServices;

namespace messageBox
{

    internal class Program
    {
        // Precisamos sempre importar a DLL aqui, que contera as funcoes a serem executadas.
        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]

        public static extern int MessageBox(IntPtr hWnd, String text, String caption, uint type);
        static void Main(string[] args)
        {
            // O primeiro argumento da funcao recebe um ponteiro para NULL
            // O segundo e o conteudo da janela
            // O terceiro e o titulo
            // E o quarto serve para configurar o comportameto da Janela, como por exemplo os botoes.
            MessageBox(IntPtr.Zero, "Hello from Pinvoke!", "Titulo Janela", 0);
        }
    }
}
```

O codigo acima funciona normalmente, você pode executa-lo em sua máquina sem nenhum problema de execução.

Mas em termos de evasão este código tem varios problemas, e neste paper vamos aprender a contornar o maior deles.

As definições de funções deste código estão sendo chamadas em texto claro, se um antivírus utilizasse regras para bloquear a função MessageBox, nosso código não funcionaria.

Existem diversas formas de se utilizar o DllImport, uma delas é com o
uso de ordinals

- Um ordinal é um index que identifica uma função em uma DLL.
- Podemos utilizá-lo para mudar os nomes das chamadas de API

Ultilizando ordinals, podermos mudar a assinatura do nosso PE.

Primeiramente, vamos ultilizar um ultilitario chamado “PEview”, ele nos permite olhar a fundo a estrutura de um PE/DLL.

Ao abrir o programa, vamos importar diretamente da system32, a dll que estamos ultilizando em nosso código, que é a user32.dll

- Após importar a DLL, clique nas seguintes opções
- SECTION .text > EXPORT ADRESS TABLE

E descendo um pouco encontramos a “MessaBoxW”, e também o valor que acompanha essa função.

![](/assets/img/1.png)

Vamos precisar desse valor no nosso código, mas vamos precisar converter o mesmo para decimal !

- Esses números podem mudar dependendo da versão do Windows

Bom, o DLLImport tem um argumento chamado EntryPoint, que ele indica o ponto de entrada para executar a função no código.

Conseguimos ultilizar o EntryPoint, com um número ou com o própio nome da função.

- Dentro desse código setamos no como EntryPoint o valor da função MessageBox.
- Porém aquele valor(index) foi convertido para decimal.

```csharp
using System;
using System.Runtime.InteropServices;

namespace messageBox
{

    internal class Program
    {
        // Precisamos sempre importar a DLL aqui, que contera as funcoes a serem executadas.
        [DllImport("user32.dll", EntryPoint = "#2154", CharSet = CharSet.Auto)]

        public static extern int Inferi(IntPtr hWnd, String text, String caption, uint type);
        static void Main(string[] args)
        {
            // O primeiro argumento da funcao recebe um ponteiro para NULL
            // O segundo e o conteudo da janela
            // O terceiro e o titulo
            // E o quarto serve para configurar o comportameto da Janela, como por exemplo os botoes.
            Inferi(IntPtr.Zero, "Inferi Gang!", "Evasion Paper", 0);
        }
    }
}
```

Como o EntryPoint da função ja está previamente setado (#2154) o nome da função, já não se torna importante fazendo assim com que possamos ultilizar o nome que quisermos, no lugar do nome da função.

Fazendo assim, que quando nosso código for análisado por EDR’S ou qualquer outro anti-virus, que faça essa verificação das chamadas de funções, bypassemos tal, pois ele não vai mais encontrar o nome da função :)

![](/assets/img/2.png)

Obrigado por ler, espero que ajude !!!

`Sit scientia tua veritas, persevera ad inferi`
