---
layout: post
title:  "Hiding System Calls Using Ordinals in C#"
author: sorahed
author_url: //twitter.com/unkvolism
description: "A little bit about how to use ordinals to hide system calls in C#"
image: /assets/img/hiding-system-calls-with-ordinals-in-cs.png
categories: c# windows 
---


# Using ordinals in C# to hide function calls

É muito comum na area de redteam, ao fazer um teste de intrusão a uma rede interna, nos depararmos com soluções de anti-virus, as quais cada dia são investidos milhões de dólares para aprimorar suas táticas de detecção.<br><br>
<br>
Sabendo disso atacantes, também buscam sempre por novas táticas para evadir essas soluções como EDR/XDR e anti-virus no geral.<br><br>
<br>
E como uma breve introdução a esse tema de evasion, vou apresentar a vocês uma coisa muito legal, que pode ser feita para “obfuscar” a chamada direta de funções no seu código.<br><br>
<br>
A técnica que vou estar mostrando hoje, é muito interessante pois ela não é muito bem documentada, e também é facil de ser executada, e funciona muito bem contra os anti-virus.<br><br>
<br>
## Vamos lá !!!
<br>
Primeiramente temos aqui, um código comum em C#.
<br>
Este código basicamente exibe uma messageBox, utilizando a dll “user32.dll” do windows.
Dentro dessa dll, se encontra a função que vamos utilizar, que é a messageBox.
<br><br>

```
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


<br><br>
O codigo acima funciona normalmente, você pode executa-lo em sua máquina sem nenhum problema de execução.
<br>
Mas em termos de evasão este código tem varios problemas, e neste paper vamos aprender a contornar o maior deles.
<br>
As definições de funções deste código estão sendo chamadas em texto claro, se um antivírus utilizasse regras para bloquear a função MessageBox, nosso código não funcionaria.
<br>
Existem diversas formas de se utilizar o DllImport, uma delas é com o
uso de ordinals
<br><br>
- Um ordinal é um index que identifica uma função em uma DLL.<br>
- Podemos utilizá-lo para mudar os nomes das chamadas de API<br>
<br><br>
Ultilizando ordinals, podermos mudar a assinatura do nosso PE.
<br>
Primeiramente, vamos ultilizar um ultilitario chamado “PEview”, ele nos permite olhar a fundo a estrutura de um PE/DLL.
<br>
Ao abrir o programa, vamos importar diretamente da system32, a dll que estamos ultilizando em nosso código, que é a user32.dll
<br>
- Após importar a DLL, clique nas seguintes opções
- SECTION .text > EXPORT ADRESS TABLE
<br>
E descendo um pouco encontramos a “MessaBoxW”, e também o valor que acompanha essa função.
<br>
![](/assets/img/1.png)
<br>
Vamos precisar desse valor no nosso código, mas vamos precisar converter o mesmo para decimal !
<br>
- Esses números podem mudar dependendo da versão do Windows
<br>
Bom, o DLLImport tem um argumento chamado EntryPoint, que ele indica o ponto de entrada para executar a função no código.
<br>
Conseguimos ultilizar o EntryPoint, com um número ou com o própio nome da função.
<br>
- Dentro desse código setamos no como EntryPoint o valor da função MessageBox.
- Porém aquele valor(index) foi convertido para decimal.
<br><br>
```
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


<br><br>
Como o EntryPoint da função ja está previamente setado (#2154) o nome da função, já não se torna importante fazendo assim com que possamos ultilizar o nome que quisermos, no lugar do nome da função.
<br>
Fazendo assim, que quando nosso código for análisado por EDR’S ou qualquer outro anti-virus, que faça essa
verificação das chamadas de funções, bypassemos tal, pois ele não vai mais encontrar o nome da função :)
<br><br><br>
![](/assets/img/2.png)
<br>
Obrigado por ler, espero que ajude !!!
<br>
`Sit scientia tua veritas, persevera ad inferi`
