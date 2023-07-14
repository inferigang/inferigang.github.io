---
layout: post
title: ELF/Rootkits Anti-Reversing Techniques
author: MatheuzSecurity
author_url: https://twitter.com/MatheuzSecurity
image: /assets/banners/rootkit.png
description: "Learn how anti-reversing techniques works"
toc: true
---

```
                          _,,,.._       ,_
                        .gMMMMMMMMMp,_    `\
                     .dMMP'       ``^YMb..dP
                    dMMP'
                    MMM:
                    YMMb.       // Pwning All the Things.
                     YMMMb.     
                      `YMM/|Mb.  ,__
                   _,,-~`--..-~-'_,/`--,,,____
               `\,_,/',_.-~_..-~/' ,/---~~~"""`\
          _,_,,,\q\q/'    \,,-~'_,/`````-,7.
         `@v@`\\,,,,__   \,,-~~"__/` ",,/MMMMb.
          `--''_..-~~\   \,-~~""  `\_,/ `^YMMMMMb..
           ,|``-~~--./_,,_  _,,-~~'/_      `YMMMMMMMb.
         ,/  `\,_,,/`\    `\,___,,,/M/'      `YMMMMMMMb
                     ;  _,,/__...|MMM/         YMMMMMMMb
                      .' /'      dMMM\         !MMMMMMMMb
                   ,-'.-'""~~~--/M|M' \        !MMMMMMMMM
                 ,/ .|...._____/MMM\   b       gMMMMMMMMM
              ,'/'\/          dMMP/'   M.     ,MMMMMMMMMP
             / `\;/~~~~----...MP'     ,MMb..,dMMMMMMMMM'
            / ,_  |          _/      dMMMMMMMMMMMMMMMMB
            \  |\,\,,,,___ _/    _,dMMMMMMMMMMMP".emmmb,
             `.\  gY.     /      7MMMMMMMMMMP"..emmMMMMM
                .dMMMb,-..|       `.~~"""```|dMMMMP'MMP'
               .MMMMP^"""/ .7 ,  _  \,---~""`^YMMP'MM;
             _dMMMP'   ,' / | |\ \\  }          PM^M^b
          _,' _,  \_.._`./  } ; \ \``'      __,'_` _  `._
      ,-~/'./'| 7`,,__,}`   ``   ``        // _/`| 7``-._`}
     |_,}__{  {,/'   ``                    `\{_  {,/'   ``
     ``  ```   ``                            ``   ``
```

# Sumário
1. O que é um ELF e Rootkit?
2. O que é reverse engineering & malware analysis?
3. Como os hackers dificultam o reversing em rootkits?
4. Técnica de Anti-Reversing de Rootkits: Sobreescrevendo o Section Header com Null Bytes
5. Técnica de Anti-Reversing em ELF usando ELFREVGO
6. Conclusão

# ELF e Rootkits
O ELF (Executable and Linkable Format) basicamente é um formato de arquivo no Linux/Unix para executáveis e bibliotecas. Nele contém informações essenciais para carregar e executar programas. O ELF também é flexível, suporta diferentes arquiteturas e pode ser estendido.

Rootkit é um tipo de malware projetado para se infiltrar e se ocultar no sistema operacional, permitindo que um hacker mantenha o acesso e o controle privilegiado dentro do sistema.

Um rootkit é capaz de modificar componentes fundamentais do sistema, como o kernel, alterar comportamentos do sistema, bibliotecas ou comandos do sistema, com o objetivo de ocultar sua presença e atividades maliciosas. Ele pode realizar várias ações prejudiciais, como coletar informações sensíveis, controlar remotamente o sistema, abrir backdoors, manipular registros de atividades para encobrir suas atividades e etc.


# Reverse Engineering e Malware Analysis
Engenharia reversa é a arte de reverter (reversing) programas, é como se você estivesse desmontando um computador ou uma cidade de lego, pra saber como foi construida e entender de fato o que está acontecendo, para depois construir ou entender como aquilo tudo foi feito.

Malware analysis é a arte de analisar ameaças feitas por outros hackers, para saber como os malwares foram feitos, quais técnicas os hackers utilizam, seja para esconder processos, fazer alterações no sistema como por exemplo um hooking, pra saber o que aquela ameaça faz no sistema, e com isso, é possivel criar regras como yara rules, pegar a hash do malware e etc, e isso também nos ajuda a saber como se proteger dessas diversas ameaças cibérneticas existentes.


# Como Hackers Dificultam o Reversing?
Os hackers hoje em dia conseguem manter a análise de seus respectivos malwares cada vez mais díficies, mas como eles fazem isso ?

Eles tornam essa análise mais difícil através de implementação de técnicas de Anti Reversing/Obfuscação.

Na sessão abaixo, iremos aprender na prática como podemos tornar nosso ELF e Rootkit (vou usar o rootkit diamorphine de exemplo) mais difícil de fazer reversing/análise.


# Técnica de Anti-Reversing de Rootkits: Sobreescrevendo o Section Header com Null Bytes
Nesta seção, abordaremos uma técnica que basicamente vamos sobreescrever o cabeçalho da seção (section header) do rootkit diamorphine com null bytes. Essa técnica tem como objetivo dificultar a análise das funções de seu .ko (kernel object) utilizando ferramentas de análise como Ghidra ou IDA.

Ao aplicarmos essa técnica, as funções do rootkit não serão exibidas nessas ferramentas e não será possível analisá-las usando recursos como o decompilador, que normalmente são de grande ajuda durante a análise e o processo de reversing de um malware.

Essa abordagem de sobreescrever o cabeçalho da seção (section header) é uma estratégia bem eficaz para dificultar a análise e proteger as funcionalidades do rootkit contra técnicas de engenharia reversa.

Bom, sem mais enrolações vamos para a prática!

```
kali@kali ~/overwrite
❯ readelf -h diamorphine.ko
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              REL (Relocatable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          0 (bytes into file)
  Start of section headers:          355416 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           0 (bytes)
  Number of program headers:         0
  Size of section headers:           64 (bytes)
  Number of section headers:         54
  Section header string table index: 53
kali@kali ~/overwrite
❯
```


O readelf é uma ferramenta usada para analisar arquivos no linux/unix. Ele fornece informações sobre a estrutura interna dos binários, como cabeçalhos, seções e símbolos. É bem útil para desenvolvedores e analistas de segurança entenderem melhor os arquivos ELF.

Como foi mostrado no output, usamos a flag "-h" do readelf no rootkit diamorphine. Essa flag "-h" basicamente vai exibir os headers do diamorphine.ko

E nela podemos ver;

- Section header string table index (53 Bytes)
-> endereço da tabela de sections.

- Number of section headers (54 Bytes)
-> Número total de seções.

- Size of section headers (64 bytes) 
-> Tamanho dos sections header

Mas ja pensaram em "zerar" esses bytes ? 

Bom, certamente, é possível "zerar" (substituir por bytes nulos) os bytes dos cabeçalhos das seções (section header) de um ELF (isso se aplica aos .ko de rootkits também). Isso pode ser feito com o objetivo de ocultar informações ou dificultar a análise sobre esse rootkit.

Ao zerar esses bytes, as informações contidas no section header ficarão indisponíveis para visualização e análise por meio de ferramentas como o readelf. Isso pode dificultar a compreensão da estrutura interna do arquivo ELF, a identificação de suas funcionalidades e recursos e principalmente o torna mais difícil ao fazer reversing.

E acreditem, podemos fazer isso com um simples script em shell!! Na sessão "ELF Anti-Reversing Techniques" irei utilizar uma ferramenta incrìvel e pouco conhecida, ela tem o foco de Anti-Reversing analysis.

```
kali@kali ~/overwrite
❯ cat -v null.sh
#!/bin/bash

overwrite() {
    local file="$1"

    local n=$(readelf -h "$file" | awk '/Number of section headers/ {print $NF}')
    local s=$(readelf -h "$file" | awk '/Size of section headers/ {print $NF}')
    local st=$(readelf -h "$file" | awk '/Section header table/ {print $NF}')

    for ((index = 0; index < n; index++)); do
        local addr=$((st + index * s + 4))

        printf '\x00\x00\x00\x00' | dd of="$file" bs=1 seek="$addr" conv=notrunc status=none
    done
}

read -p "Enter with path your ELF: " elf
overwrite "$elf"
kali@kali ~/overwrite
❯
```

Bom, neste script (foi baseado em uma função do ELFREVGO) basicamente estamos definindo uma função chamada "overwrite" que recebe o PATH do ELF/Rootkit.

Logo depois usamos o readelf para pegar as informações da section header do "diamorphine.ko", e usando o comando awk para extrair informações específicas desse cabeçalho.

Depois fizemos um loop for que itera sobre as seções do .ko, o loop é executado de 0 até o número de seções. A cada iteração, o índice da seção é usado para calcular o endereço (addr) do tipo de seção. O endereço é calculado adicionando um deslocamento ao endereço base da tabela de seções e ao tamanho dos cabeçalhos de seção multiplicado pelo índice da seção (index * size_of_section_headers + 4). 

E Dentro do loop, usamos o comando printf para criar uma sequência de quatro null bytes (\x00\x00\x00\x00). Em seguida, o comando "dd" é usado para sobreescrever os quatro bytes do .ko, o parâmetro of="$file" especifica o arquivo de destino, bs=1 indica que a operação é realizada em blocos de 1 byte, seek="$addr" define o deslocamento no arquivo onde os bytes serão escritos e conv=notrunc garante que o arquivo não seja truncado antes de escrever os bytes. A opção status=none é usada para suprimir a saída do dd.

E por fim, usamos o "read" que utilizamos para atribuí-la a uma variável chamada "elf".

Muito simples, interessante e fácil né ? Bom, agora é a hora da mágica!!

```
kali@kali ~/overwrite
❯ ./null.sh
Enter with path your ELF: diamorphine.ko
kali@kali ~/overwrite
❯ readelf -h diamorphine.ko
ELF Header:
  Magic:   7f 45 4c 46 00 00 00 00 00 00 00 00 00 00 00 00
  Class:                             none
  Data:                              none
  Version:                           0
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              REL (Relocatable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          0 (bytes into file)
  Start of section headers:          0 (bytes into file)
  Flags:                             0x0
  Size of this header:               27736 (bytes)
  Size of program headers:           5 (bytes)
  Number of program headers:         0
  Size of section headers:           0 (bytes)
  Number of section headers:         0
  Section header string table index: 0
kali@kali ~/overwrite
❯ readelf -S diamorphine.ko
There are no sections in this file.
kali@kali ~/overwrite
❯ sudo insmod diamorphine.ko
kali@kali ~/overwrite
❯ kill -63 0 && lsmod|grep diamorphine
diamorphine            16384  0
kali@kali ~/overwrite
❯ sudo rmmod diamorphine
kali@kali ~/overwrite
❯
```

Agora, quando fomos colocar o "diamorphine.ko", no ghidra para análisar suas funções, não vamos conseguir visualizar nenhuma de suas funções.

# ELF Anti-Reversing Techniques
Nesta seção, iremos utilizar a ferramenta chamada ELFREVGO que é uma ferramenta anti-análise que ofusca um ELF.

Para baixar esta ferramenta é bem simples.
```
kali@kali ~
❯ git clone https://github.com/Trigleos/ELFREVGO
Cloning into 'ELFREVGO'...
remote: Enumerating objects: 72, done.
remote: Counting objects: 100% (72/72), done.
remote: Compressing objects: 100% (51/51), done.
remote: Total 72 (delta 32), reused 45 (delta 17), pack-reused 0
Receiving objects: 100% (72/72), 7.37 MiB | 11.96 MiB/s, done.
Resolving deltas: 100% (32/32), done.
kali@kali ~
❯ cd ELFREVGO/bin/
kali@kali ~/ELFREVGO/bin (main)
❯ ls
ELFREVGO*
kali@kali ~/ELFREVGO/bin (main)
❯ ./ELFREVGO -h
Usage of ./ELFREVGO:
  -b  change number of bits (32 or 64) of ELF
  -e  change endianness of ELF
  -f string
      name of the ELF file you want to change
  -g  overwrite library function with another function
  -gd string
      name of the library function that you want to replace
  -gf string
      name of the function that you want to call instead of the library function
  -gx string
      hexadecimal address that you want to call instead of the library function
  -n  overwrite section names with null bytes
  -o string
      name of output ELF file
  -t  overwrite section types with null bytes
kali@kali ~/ELFREVGO/bin (main)
❯
```

Nela temos diversas técnicas muito interessantes de anti-reversing no qual podemos utilizar para ofuscar um malware, ELF, etc.

Vamos usar uma feature do ELFREVGO, a flag "-b" que basicamente altera o numero de bits.

```
kali@kali ~/ELFREVGO/bin (main)
❯ file bin
bin: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7651fe1bd45e049907f9d9e1438a03e764d1614f, for GNU/Linux 3.2.0, not stripped
kali@kali ~/ELFREVGO/bin (main)
❯ ./ELFREVGO -f bin -b -o bin2
kali@kali ~/ELFREVGO/bin (main)
❯ file bin2
bin2: ELF 32-bit LSB executable, x86-64, version 1 (SYSV), no program header, no section header
kali@kali ~/ELFREVGO/bin (main)
❯ gdb -q bin2

BFD: warning: /home/kali/ELFREVGO/bin/bin2 has a section extending past end of file
"/home/kali/ELFREVGO/bin/bin2": not in executable format: file format not recognized
(gdb) run
Starting program:
No executable file specified.
Use the "file" or "exec-file" command.
(gdb) b main
No symbol table is loaded.  Use the "file" command.
```
E pronto!

Esta seção é mais um "bônus", para demonstrar uma feature de uma ferramenta não muito conhecida mas muito útil e bem interessante para ELF Anti-Analysis.

# Conclusão
Bom, estamos no fim deste paper, espero que realmente tenham gostado, se tiverem qualquer duvida estou disposto a ajudar, é so entrar em contato comigo pelo twitter <a href="//twitter.com/MatheuzSecurity">@MatheuzSecurity</a>. 

Muito obrigado por lerem!! Cya hackers!

#InferiGang2Years!!!

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
⠀⠀⠀⠀⠀⠀⢠⣭⣾⣿⠃⣿⡇⣿⣿⡷⢾⣭⡓⠀⠀⠀⠀⠀- Pwn All The Things.⠀⠀⠀
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
