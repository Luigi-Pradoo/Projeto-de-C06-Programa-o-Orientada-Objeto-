# Casos de teste (capturas .pcap)

Cada arquivo testa uma situação. Todos foram **gerados por script** (não foram gravados em uma
rede real): os bytes de cada pacote foram montados como uma placa de rede gravaria
(Ethernet → IPv4 → TCP/ICMP/UDP). Os alvos são os servidores da **Empresa Exemplo**, que o
programa cadastra sozinho na primeira execução:

| Servidor | IP |
|----------|----|
| Servidor Web | 10.0.0.10 |
| Servidor de Arquivos | 10.0.0.20 |
| Servidor de E-mail | 10.0.0.25 |

## Como rodar um caso

No menu: **6** (analisar) → empresa **1** (Empresa Exemplo) → fonte **2** (arquivo) →
caminho, por exemplo `exemplos\testes\02-syn-flood.pcap`.

Depois, a opção **7** mostra os alertas salvos da empresa.

## Resultados esperados

| Arquivo | Situação | Resultado esperado |
|---------|----------|--------------------|
| `01-trafego-normal.pcap` | Só uso normal: clientes acessando os servidores, pings e DNS | **0 alertas** (1350 pacotes lidos, 150 de DNS/UDP ignorados) |
| `02-syn-flood.pcap` | 400 pedidos de conexão em 0,8 s do IP 203.0.113.66 contra a porta 80 | **1 alerta: SYN Flood** (Crítica) |
| `03-port-scan.pcap` | 203.0.113.200 testa 100 portas diferentes do servidor de arquivos, devagar (25 por segundo) | **1 alerta: Port Scan** (Alta). Não dispara SYN Flood, porque o ritmo é baixo |
| `04-portas-suspeitas.pcap` | 198.51.100.23 acessa as portas 23, 4444, 6667 e 31337 do servidor de e-mail | **4 alertas: Porta suspeita** (Alta), um por porta |
| `05-pacote-gigante.pcap` | Um pacote TCP de 9000 bytes e um ICMP de 4000 bytes | **2 alertas: Tamanho anormal** (Baixa) |
| `06-limite-exato.pcap` | Exatamente no limite: 100 SYN em 1 s, 20 portas em 3 s, pacote de 1500 bytes | **0 alertas**. A regra é "mais que o limite" |
| `07-acima-do-limite.pcap` | Um a mais que o limite: 101 SYN, 21 portas, 1501 bytes | **3 alertas**: SYN Flood, Port Scan e Tamanho anormal |
| `08-formato-pcapng.pcapng` | Captura salva no formato padrão do Wireshark (pcapng) | **Mensagem de erro** explicando como salvar no formato pcap |
| `09-nao-e-captura.pcap` | Um arquivo de texto com extensão .pcap | **Mensagem de erro**: "o arquivo não é uma captura pcap" |
| `10-captura-vazia.pcap` | Captura sem nenhum pacote | **Aviso**: nenhum pacote IPv4 com TCP ou ICMP encontrado |

Os casos 06 e 07 testam a **fronteira** das regras: mostram que o limite é respeitado exatamente.
Os casos 08 a 10 testam o **tratamento de erros**: o programa avisa e volta ao menu, sem travar.

A captura `exemplos/captura-exemplo.pcap` (fora desta pasta) mistura tudo: navegação normal e uma
varredura estilo nmap de um computador contra o roteador `192.168.0.1`.
