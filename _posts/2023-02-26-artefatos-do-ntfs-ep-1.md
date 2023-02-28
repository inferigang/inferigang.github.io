---
layout: post
author: astreuzz
author_url: https://twitter.com/astreuzz
title: "Artefatos do NTFS, Ep. 1: Introdução"
description: "Uma abordagem sobre recursos internos do NTFS e suas aplicações em Red Teaming e Análise Forense"
banner_path: /assets/img/ntfs-artifacts-banner.png
---

# Introdução

Há alguns anos atrás, quando a era do Windows NT estava a começar, fomos introduzidos a um novo sistema de arquivos para os sistemas da Microsoft, o NTFS. Agora, como substituto do antigo e mais simples FAT, as novas versões do Windows portavam desse sistema, além é claro de outros recursos presentes até hoje como BitLocker. A adição desse novo sistema de arquivos trouxe consigo novos recursos a serem estudados, dos quais muitos futuramente viriam a ser quase que esquecidos. Nessa série de papers, discorrerei sobre as aplicações práticas de recursos internos do NTFS voltados para Red Teaming e Análise Forense.

# Sobre o NTFS

Um dos diferenciais da versão New Technology (NT) do Windows foram recursos como BitLocker e o próprio NTFS que, como mencionado, prevalecem até hoje em versões recentes do Windows. O NTFS, diferentemente do FAT que era usado em até então como sistema padrão, trouxe consigo recursos interessantes como suporte a journaling, TxF e uma capacidade maior de armazenamento. Apesar disso, sua análise é suficientemente simples de ser feita bit a bit devida a sua estrutura B-Tree, claro, passando longe de ser uma tarefa legal de ser feita. Por hoje, focaremos principalmente na estrutura do NTFS baseando-se em diagramas e, nos próximos eps., veremos na prática uma análise bit a bit de um dispositivo com NTFS.

<img src="/assets/img/ntfs-artifacts-img-basics.png">

# Boot Sector e Bootkits: Uma breve introdução

Os primeiros bytes de uma partição NTFS, o boot sector, contém informações da partição (OEM ID) e para inicialização do sistema Windows. No boot sector é armazenado o IPL (Initial Program Loader), ocupando a área do bootstrap code. Os bootkits em geral visam o ataque ao boot sector, injetando códigos para obter controle sobre a inicialização do sistema operacional.

> Por hoje não focaremos tanto nessa área, futuramente postaremos sobre Bootkits e análise forense na prática, aguardem.

# Master File Table ($MFT)

A Master File Table é o coração do NTFS, nela são armazenados os metadadoos dos arquivos, como MACB timestamps, flags, nome do arquivo, etc. Aqui, entramos em uma área muito importante para analistas forense e red teamers, já que por se tratar do local onde são armazenado os arquivos em sí, conteúdos, metadados, etc. é interessante que se tenha o conhecimento de como esconder seus rastros em disco e, para uma analista, como buscá-los. Uma das técnicas de se fazer isso é utilizando de ataques fileless que, apesar de não entrarem em contato direto com a MFT, ainda deixam rastros para analistas, sejam eles logs de acesso ou algum contato indireto com o disco.

## Sobre o Armazenamento dos Arquivos

Para cada arquivo no sistema, existe um registro na MFT referente a aquele arquivo. Esse registro começa com o magic `FILE0` e possui algumas divisões chamadas de atributo. O primeiro atributo, chamado $STANDARD_INFORMATION, armazena metadados como data de criação, flags, permissões, etc. Outro atributo importante, $FILE_NAME, também armazena a data de criação do arquivo, entretanto esse é um atributo muito útil para analistas forense, algo que entenderemos mais à frente.

<img src="/assets/img/ntfs-artifacts-img-file0.png">

## $DATA

O atributo $DATA, armazena nada mais nada menos que o conteúdo do arquivo em sí. Apesar de sua descrição simples, esse atributo possui um recurso herdado (copiado) do HPFS chamado Alternate Data Streams. No NTFS todo arquivo armazena seu conteúdo no atributo $DATA, todavia esse atributo pode ser dividido em vários, o que chamamos de Alternate Data Streams.

Para ser mais exato, todo arquivo possui ao menos uma stream chamada Unnamed Stream, onde é armazenado o conteúdo do arquivo por padrão. Podemos acessar essa stream normalmente ao abrir um arquivo ou pelo `cmd.exe`:

<img src="/assets/img/ntfs-artifacts-img-unnamed-stream.png">

Não existe um limite para o número de streams que um arquivo pode ter, assim como o tipo de conteúdo que será armazenado. Em uma alternate stream podemos armazenar qualquer arquivo, texto, música, binários, etc. Vejamos um exemplo de criação de uma alternate stream chamada wizard no arquivo `inferi.txt`:

<img src="/assets/img/ntfs-artifacts-img-wizard-stream.png">

Uma informação interessante sobre as streams alternativas é que NÃO são visíveis pelo `Explorer.exe`, apenas por comandos ou programas específicos. Devida a essa característica, esse é um recurso que já foi utilizado por grupos APTs para diversos propósitos.

## $STANDARD_INFORMATION e Timestomping

O atributo $STANDARD_INFORMATION armazena basicamente todas as informações observáveis de um arquivo. Quando navegamos pelo `Explorer.exe`, as informações obtidas como metadados, tamanho do arquivo, nome do arquivo, etc. são armazenadas aqui.

<img src="/assets/img/ntfs-artifacts-img-explorer.png">

Esse é um atributo interessante pois temos total controle sobre alguns de seus dados como data de criação. Devida a essa característica, podemos efetuar uma técnica chamada Timestomping que consiste basicamente em modificar o timestamp de um arquivo com o objetivo de falsificar evidências. Essa técnica pode ser efetuada simplesmente com alguns comandos do Powershell:

<img src="/assets/img/ntfs-artifacts-img-timestomping.png">

## O “Anti-timestomping”: $FILE_NAME

Como mencionei, ambos $STANDARD_INFORMATION e $FILE_NAME armazenam metadados, em especial, MACB timestamps. A principal diferença entre eles é que, enquanto as informações dispostas em $STANDARD_INFORMATION são modificáveis via software, no $FILE_NAME não. Devida a essa característica, o atributo $FILE_NAME tem importante valor para uma análise forense quando analisamos indicações de remoção (IR). Nos próximos eps. veremos uma análise prática e comparativa de ambos os atributos.

# Ad Astra

O NTFS é com certeza um sistema com diversos recursos interessantes, tanto para o red team quanto forensics. Por hoje, chego ao fim do primeiro ep. dessa série de papers, espero tê-lo como leitor novamente, obrigado.

# Fontes

- [https://attack.mitre.org/techniques/T1070/006/](https://attack.mitre.org/techniques/T1070/006/)
- [https://attack.mitre.org/techniques/T1564/004/](https://attack.mitre.org/techniques/T1564/004/)
- [http://ntfs.com/ntfs_basics.htm](http://ntfs.com/ntfs_basics.htm)
- [http://www.c-jump.com/bcc/t256t/Week04NtfsReview/index.html](http://www.c-jump.com/bcc/t256t/Week04NtfsReview/index.html)