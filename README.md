# Sentinela — Sistema de Detecção de Anomalias em Redes

Projeto final da disciplina **C06 – Programação Orientada a Objetos** (NP2) — Inatel.
Prof. Christopher Lima.

O Sentinela vigia os servidores das empresas cadastradas. Você cadastra uma empresa e os
servidores dela (nome e endereço IP), e o sistema analisa o tráfego que chega a esses servidores,
pacote por pacote, avisando quando encontra sinais de ataque. O tráfego pode ser **simulado** ou
**real**, lido de uma captura do Wireshark. Os cadastros, as análises e os
alertas ficam guardados em um **banco de dados SQLite**. É uma versão didática do que um IDS
(*Intrusion Detection System*) faz em uma rede de verdade.

## Integrantes

| Nome | Matrícula | Curso | Parte do projeto pela qual responde |
|------|-----------|-------|-------------------------------------|
| _preencher_ | _preencher_ | _preencher_ | 1. Modelo (`modelo`) |
| _preencher_ | _preencher_ | _preencher_ | 2. Detectores (`detector`) |
| _preencher_ | _preencher_ | _preencher_ | 3. Análise (`analise`) |
| _preencher_ | _preencher_ | _preencher_ | 4. Banco, erros e menu (`banco`, `excecao`, `Principal`) |

## O que o sistema faz

**Cadastro (salvo no banco):** cadastrar, listar e excluir empresas e servidores.

**Análise:** escolhida uma empresa, o sistema obtém o tráfego de uma de duas fontes e passa cada
pacote por quatro detectores:

- **Simulado:** 20.000 pacotes chegando aos servidores da empresa, com quatro ataques no meio;
- **Arquivo de captura `.pcap`:** tráfego real, gravado com o Wireshark (veja a seção
  [Analisar a sua própria rede](#analisar-a-sua-própria-rede-wireshark)).

| Anomalia | Como é reconhecida | Severidade |
|----------|--------------------|------------|
| **SYN Flood** | mais de 100 pedidos de conexão TCP (SYN) do mesmo IP em 1 segundo | Crítica |
| **Port Scan** | mais de 20 portas diferentes do mesmo servidor testadas pelo mesmo IP em 3 segundos | Alta |
| **Porta suspeita** | tráfego para portas como 23 (Telnet), 4444, 6667 e 31337 | Alta |
| **Tamanho anormal** | pacote maior que 1500 bytes (tamanho máximo de uma rede Ethernet) | Baixa |

Cada alerta aparece na tela e é gravado no banco, ligado ao servidor atacado.

**Modo ao vivo (opcional):** durante a análise, o tráfego aparece na tela — uma amostra de 1 pacote
a cada 200, mais todos os pacotes que geraram alerta (marcados com `<<< SUSPEITO`, com o alerta
logo abaixo) e uma linha de progresso a cada 25%.

```
  [ 3000] TCP 192.168.1.41:63940 -> 10.0.0.25:443 196 bytes
  [ 3101] TCP 203.0.113.66:60885 -> 10.0.0.10:80 [SYN] 60 bytes   <<< SUSPEITO
[ALERTA] #1 [CRITICA] 12:01:12 | SYN Flood | de 203.0.113.66 | 101 pedidos de conexão em 1000 ms ...
  [ 3200] TCP 203.0.113.66:62026 -> 10.0.0.10:80 [SYN] 60 bytes
  ...... 5000 de 20000 pacotes analisados (25%), 1 alerta(s) até agora ......
```

**Histórico (consultado no banco):** últimas análises e as anomalias da última análise, da mais
grave para a menos grave.

**Relatório de anomalias da rede (consultado no banco):** para uma empresa, tudo o que já foi
detectado nas análises dela, agrupado por tipo de ataque, por IP de origem e por servidor
atacado (com barras proporcionais), e a lista completa das anomalias.

## Como executar

Requisito: **JDK 17 ou superior**. O driver do banco já vem na pasta `lib`.

**Windows:** dê dois cliques em **`executar.bat`**, ou rode no PowerShell, dentro da pasta do projeto:

```powershell
.\executar.bat
```

**Linux / macOS:** `./executar.sh`

**IDE (IntelliJ, Eclipse, VS Code):** abra a pasta do projeto (a IDE lê o `pom.xml` e baixa o
driver sozinha) e execute a classe `br.inatel.sentinela.Principal`.

**Terminal, sem o script (Windows):**

```powershell
javac -encoding UTF-8 -d out -cp lib\sqlite-jdbc-3.47.1.0.jar -sourcepath src\main\java src\main\java\br\inatel\sentinela\Principal.java
java -cp "out;lib\sqlite-jdbc-3.47.1.0.jar" br.inatel.sentinela.Principal
```

(No Linux/macOS, troque `\` por `/` e o `;` do classpath por `:`.)

Na primeira execução o banco está vazio, então o programa cadastra sozinho uma **Empresa
Exemplo** com 3 servidores, para a análise funcionar de cara.

```
=== SENTINELA - Detecção de Anomalias em Redes ===
1 - Cadastrar empresa
2 - Cadastrar servidor
3 - Listar empresas e servidores
4 - Excluir empresa
5 - Excluir servidor
6 - Analisar a rede de uma empresa
7 - Ver histórico de análises
8 - Relatório de anomalias da rede de uma empresa
0 - Sair
```

## Analisar a sua própria rede (Wireshark)

> **Só analise a sua própria rede, ou uma rede em que você tenha autorização.** Capturar o tráfego
> de outras pessoas (Wi-Fi de café, da faculdade, de vizinhos) é interceptação de comunicação e é
> crime; varrer portas de equipamentos que não são seus também não é permitido.

1. Instale o [Wireshark](https://www.wireshark.org/) (no Windows, junto com o Npcap).
2. Rode `ipconfig` e anote o IPv4 do seu computador e o **Gateway Padrão** (o seu roteador).
3. No Sentinela, cadastre uma empresa (ex.: "Minha Casa") e um servidor "Roteador" com o IP do gateway.
4. No Wireshark, capture na interface **Wi-Fi**. Navegue, rode `ping` no roteador e, para ver
   alertas, `nmap <ip-do-seu-roteador>` ([nmap.org](https://nmap.org/)).
5. Pare a captura e use **Arquivo > Salvar como**, tipo **"Wireshark/tcpdump/... - pcap"**
   (o padrão, pcapng, não é aceito).
6. No Sentinela: opção 6 → a empresa → fonte `2` → caminho do arquivo.

O projeto traz `exemplos/captura-exemplo.pcap` para teste. **Ela não foi gravada numa rede real:**
foi gerada por um script, com os bytes de cada pacote montados como uma placa de rede gravaria,
imitando navegação HTTPS, DNS, pings e uma varredura estilo nmap do computador `192.168.0.15`
contra o roteador `192.168.0.1`. Resultado: Port Scan, SYN Flood, Porta suspeita (Telnet) e um
pacote de tamanho anormal; a navegação normal não gera alerta.

## Banco de dados

SQLite, em um único arquivo: `dados/sentinela.db` (criado na primeira execução). Acesso por
**JDBC**, todo concentrado na classe `banco/BancoDeDados`.

| Tabela | Conteúdo |
|--------|----------|
| `empresas` | id, nome, CNPJ (único), responsável, e-mail |
| `servidores` | id, empresa_id, nome, IP |
| `analises` | id, empresa_id, data e hora, pacotes, anomalias |
| `anomalias` | id, analise_id, servidor_id, tipo, severidade, IP suspeito, IP alvo, descrição... |

As tabelas são ligadas por chaves estrangeiras. Ao excluir uma empresa, o banco apaga junto os
servidores e as análises dela (`ON DELETE CASCADE`).

Para ver o conteúdo fora do programa, abra `dados/sentinela.db` no
[DB Browser for SQLite](https://sqlitebrowser.org/).

## Organização do código

24 tipos em 5 pacotes:

```
src/main/java/br/inatel/sentinela/
├── Principal.java     menu: cadastro, análise, histórico e relatório
├── modelo/            Empresa, Servidor, PacoteRede, PacoteTcp, PacoteIcmp, Anomalia, Severidade
├── detector/          Detector (abstrata), DetectorSynFlood, DetectorPortScan, DetectorPortaSuspeita, DetectorTamanhoAnormal
├── analise/           MotorDeteccao, MonitorAoVivo, FonteDeTrafego (interface), SimuladorTrafego, LeitorPcap,
│                      Notificador (interface), NotificadorConsole
├── banco/             BancoDeDados (SQLite via JDBC)
└── excecao/           SentinelaException, CadastroInvalidoException, BancoDeDadosException
lib/                   driver JDBC do SQLite
exemplos/              captura-exemplo.pcap (gerada por script, para teste)
docs/uml/              diagramas UML
```

## Critérios do edital e onde cada um está

| # | Critério | Onde ver no código |
|---|----------|--------------------|
| 01 | Boas práticas | Pacotes por responsabilidade, atributos `private final`, constantes nomeadas, Javadoc, convenções do Java |
| 02 | Classes | `Empresa`, `Servidor`, `Anomalia`, `BancoDeDados`... (atributos, construtores, métodos, membro `static`) |
| 03 | Herança | `PacoteRede` → `PacoteTcp`/`PacoteIcmp`; `Detector` → 3 detectores; `SentinelaException` → 2 exceções |
| 04 | Polimorfismo | `MotorDeteccao` chama `analisar()` em cada `Detector` e `notificar()` em cada `Notificador`; `fonte.obterPacotes()` simula ou lê o arquivo, conforme o objeto; `descrever()` em cada pacote (usado pelo `MonitorAoVivo`); sobrecarga de construtores em `Empresa`, `Servidor` e `Anomalia` |
| 05 | Interfaces **e** classes abstratas | Interfaces: `Notificador` e `FonteDeTrafego` (e `Comparable`/`AutoCloseable` do Java). Abstratas: `PacoteRede`, `Detector` |
| 06 | Tratamento de erros | 3 exceções próprias; validação nos construtores de `Empresa` e `Servidor`; `try/catch` no menu; `try-with-resources` no banco |
| 07 | Arquivos **e** banco de dados | Banco: SQLite via JDBC em `BancoDeDados` — cadastro (INSERT, SELECT, DELETE), histórico e relatório (JOIN, GROUP BY, COUNT). Arquivos: leitura de capturas `.pcap` em `LeitorPcap` |
| 08 | Threads | **Não utilizadas, por orientação do professor.** A análise é sequencial, um pacote de cada vez |
| 09 | UML completo | `docs/uml/` |
| 10 | Repositório | este repositório |
| 11 | Relevância ao curso | Redes de computadores e segurança: camadas Ethernet, IPv4, TCP e ICMP lidas byte a byte, portas, MTU, varredura de portas e negação de serviço |
| 12 | Uso de IA | seção abaixo |

## Diagrama UML

O diagrama completo, com todos os atributos, métodos e relacionamentos, está em
[`docs/uml/diagrama-classes-completo.pdf`](docs/uml/diagrama-classes-completo.pdf)
(também em [PNG](docs/uml/diagrama-classes-completo.png) e [SVG](docs/uml/diagrama-classes-completo.svg)).
Há um diagrama por pacote em [`docs/uml/pacotes/`](docs/uml/pacotes/).

![Visão geral das classes](docs/uml/visao-geral.png)

## Uso de Inteligência Artificial

**O grupo utilizou IA? Sim.**

**Ferramenta:** Claude, da Anthropic, pelo aplicativo Claude.

**Como foi utilizada:**

- A partir do tema ("sistema de detecção de anomalias em redes") e dos critérios do edital, a IA
  propôs a arquitetura (pacotes, hierarquias de classes, interfaces) e **gerou o código-fonte Java**
  deste repositório, incluindo o cadastro e o banco de dados.
- A pedido do grupo, a IA acrescentou o modo ao vivo e o relatório de anomalias, e fez uma
  revisão do código que corrigiu a validação de endereços IP e a numeração das anomalias.
- A pedido do grupo, a IA acrescentou o detector de Port Scan e a leitura de capturas `.pcap`
  (interface `FonteDeTrafego`, classe `LeitorPcap`), e gerou por script a captura de exemplo
  `exemplos/captura-exemplo.pcap`.
- A IA **gerou os diagramas UML** a partir do código compilado, os scripts de execução e **este README**.
- A IA produziu um material de estudo explicando as decisões de projeto e os conceitos de
  orientação a objetos usados, que o grupo utilizou para estudar o código.

**O que foi feito pelo grupo:** escolha do tema, definição dos requisitos e pedidos de mudança à IA
(simplificação, cadastro de empresas e servidores, banco de dados, modo ao vivo, relatório, Port
Scan e leitura de capturas do Wireshark). Contribuições de cada integrante (estudo, testes,
extensões implementadas, organização do repositório):

- _Nome 1_: _preencher com o que fez de fato (ex.: extensão implementada, testes, estudo da parte 1)_
- _Nome 2_: _preencher_
- _Nome 3_: _preencher_
- _Nome 4_: _preencher_

## Limitações conhecidas

- Não há captura ao vivo na placa de rede: o tráfego real vem de um arquivo gravado pelo Wireshark.
- O leitor aceita só o formato pcap (não o pcapng) e só IPv4; o arquivo é lido inteiro para a memória.
- As regras são limites fixos, sem aprendizado do comportamento normal da rede.
- A análise é sequencial: o projeto não usa threads, por orientação do professor.
- Não há edição de cadastro: para corrigir um dado, exclua e cadastre de novo.
- O simulador usa uma semente fixa (`Random(42)`): a mesma empresa gera sempre o mesmo tráfego,
  o que deixa a demonstração previsível; por isso análises repetidas encontram os mesmos ataques.
- A validação do CNPJ confere só os 14 dígitos, não os dígitos verificadores.
