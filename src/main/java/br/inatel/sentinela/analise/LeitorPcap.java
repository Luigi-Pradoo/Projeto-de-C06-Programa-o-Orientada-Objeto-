package br.inatel.sentinela.analise;

import br.inatel.sentinela.excecao.SentinelaException;
import br.inatel.sentinela.modelo.PacoteIcmp;
import br.inatel.sentinela.modelo.PacoteRede;
import br.inatel.sentinela.modelo.PacoteTcp;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Lê tráfego REAL de um arquivo de captura no formato pcap, o formato clássico
 * do Wireshark e do tcpdump.
 *
 * Um arquivo pcap é uma sequência de bytes:
 *   cabeçalho do arquivo (24 bytes) -> diz a ordem dos bytes e o tipo de rede;
 *   para cada pacote: cabeçalho (16 bytes, com instante e tamanho) + os bytes
 *   do pacote como passaram na rede (Ethernet -> IPv4 -> TCP ou ICMP).
 *
 * Esta classe percorre esses bytes e cria os mesmos objetos PacoteTcp e
 * PacoteIcmp que o simulador cria. Pacotes de outros tipos (IPv6, UDP, ARP...)
 * são contados como ignorados, porque os detectores não os analisam.
 */
public class LeitorPcap implements FonteDeTrafego {

    // Números "mágicos" que abrem o arquivo e identificam o formato.
    private static final int MAGICO_MICROSSEGUNDOS = 0xA1B2C3D4;
    private static final int MAGICO_NANOSSEGUNDOS = 0xA1B23C4D;
    private static final int MAGICO_PCAPNG = 0x0A0D0D0A;

    // Tipos de rede (enlace) que o leitor entende.
    private static final int ENLACE_ETHERNET = 1;
    private static final int ENLACE_IP_PURO = 101;
    private static final int ENLACE_LINUX_SLL = 113;

    // Valores dos campos dentro dos pacotes.
    private static final int ETHERTYPE_IPV4 = 0x0800;
    private static final int ETHERTYPE_VLAN = 0x8100;
    private static final int PROTOCOLO_ICMP = 1;
    private static final int PROTOCOLO_TCP = 6;
    private static final int FLAG_SYN = 0x02;
    private static final int FLAG_ACK = 0x10;

    private final Path arquivo;
    private int pacotesIgnorados;

    public LeitorPcap(Path arquivo) {
        if (arquivo == null) {
            throw new IllegalArgumentException("informe o caminho do arquivo de captura");
        }
        this.arquivo = arquivo;
    }

    @Override
    public List<PacoteRede> obterPacotes() throws SentinelaException {
        byte[] dados;
        try {
            dados = Files.readAllBytes(arquivo);
        } catch (NoSuchFileException e) {
            throw new SentinelaException("arquivo não encontrado: " + arquivo.toAbsolutePath());
        } catch (IOException e) {
            throw new SentinelaException("não foi possível ler o arquivo " + arquivo, e);
        }

        ByteBuffer buffer = ByteBuffer.wrap(dados);
        if (dados.length < 24) {
            throw new SentinelaException("o arquivo é pequeno demais para ser uma captura pcap");
        }

        // 1) Cabeçalho do arquivo: o número mágico revela a ordem dos bytes.
        int magico = buffer.getInt(0);
        if (magico == MAGICO_PCAPNG) {
            throw new SentinelaException("o arquivo está no formato pcapng. No Wireshark, use"
                    + " Arquivo > Salvar como e escolha \"Wireshark/tcpdump/... - pcap\"");
        }
        if (magico != MAGICO_MICROSSEGUNDOS && magico != MAGICO_NANOSSEGUNDOS) {
            buffer.order(ByteOrder.LITTLE_ENDIAN); // gravado ao contrário, como no Windows
            magico = buffer.getInt(0);
        }
        if (magico != MAGICO_MICROSSEGUNDOS && magico != MAGICO_NANOSSEGUNDOS) {
            throw new SentinelaException("o arquivo não é uma captura pcap: " + arquivo.getFileName());
        }
        boolean nanossegundos = magico == MAGICO_NANOSSEGUNDOS;
        int enlace = buffer.getInt(20);
        if (enlace != ENLACE_ETHERNET && enlace != ENLACE_IP_PURO && enlace != ENLACE_LINUX_SLL) {
            throw new SentinelaException("tipo de rede " + enlace + " não suportado (use uma captura Ethernet ou Wi-Fi)");
        }

        // 2) Um registro por pacote, até o fim do arquivo.
        List<PacoteRede> pacotes = new ArrayList<>();
        pacotesIgnorados = 0;
        buffer.position(24);
        while (buffer.remaining() >= 16) {
            long segundos = buffer.getInt() & 0xFFFFFFFFL;
            long fracao = buffer.getInt() & 0xFFFFFFFFL;
            int bytesGravados = buffer.getInt();
            buffer.getInt(); // tamanho original na rede: não usado, o tamanho vem do cabeçalho IP
            if (bytesGravados < 0 || bytesGravados > buffer.remaining()) {
                break; // arquivo cortado no meio de um pacote: fica com o que deu para ler
            }
            int inicio = buffer.position();
            buffer.position(inicio + bytesGravados);

            long instanteMs = segundos * 1000 + (nanossegundos ? fracao / 1_000_000 : fracao / 1000);
            PacoteRede pacote = decodificar(dados, inicio, inicio + bytesGravados, enlace, instanteMs);
            if (pacote == null) {
                pacotesIgnorados++;
            } else {
                pacotes.add(pacote);
            }
        }
        return pacotes;
    }

    @Override
    public String descrever() {
        return "arquivo " + arquivo.getFileName() + "; " + pacotesIgnorados
                + " pacote(s) ignorado(s) por não serem IPv4 com TCP ou ICMP";
    }

    public int getPacotesIgnorados() {
        return pacotesIgnorados;
    }

    /**
     * Transforma os bytes de um pacote em PacoteTcp ou PacoteIcmp.
     *
     * @return o pacote, ou null se ele não for IPv4 com TCP ou ICMP
     */
    private PacoteRede decodificar(byte[] dados, int inicio, int fim, int enlace, long instanteMs) {
        // Camada de enlace: descobre onde começa o cabeçalho IP.
        int ip;
        if (enlace == ENLACE_ETHERNET) {
            if (fim - inicio < 14) {
                return null;
            }
            int etherType = numero16(dados, inicio + 12);
            ip = inicio + 14;
            if (etherType == ETHERTYPE_VLAN && fim - inicio >= 18) {
                etherType = numero16(dados, inicio + 16); // rede com VLAN: 4 bytes a mais
                ip = inicio + 18;
            }
            if (etherType != ETHERTYPE_IPV4) {
                return null;
            }
        } else if (enlace == ENLACE_LINUX_SLL) {
            if (fim - inicio < 16 || numero16(dados, inicio + 14) != ETHERTYPE_IPV4) {
                return null;
            }
            ip = inicio + 16;
        } else {
            ip = inicio;
        }

        // Camada de rede: cabeçalho IPv4.
        if (fim - ip < 20 || (dados[ip] & 0xFF) >> 4 != 4) {
            return null;
        }
        int tamanhoCabecalhoIp = (dados[ip] & 0x0F) * 4;
        // Tamanho do pacote IP, sem o cabeçalho Ethernet: é a medida que o limite de 1500
        // bytes (MTU) usa. Algumas placas gravam 0 aqui quando juntam pacotes grandes
        // (offload); nesse caso o tamanho vem do que foi gravado no arquivo.
        int tamanho = numero16(dados, ip + 2);
        if (tamanho == 0) {
            tamanho = fim - ip;
        }
        int deslocamentoFragmento = numero16(dados, ip + 6) & 0x1FFF;
        if (deslocamentoFragmento != 0) {
            return null; // pedaço do meio de um pacote fragmentado: não tem cabeçalho TCP/ICMP
        }
        int protocolo = dados[ip + 9] & 0xFF;
        String origem = enderecoIp(dados, ip + 12);
        String destino = enderecoIp(dados, ip + 16);
        int transporte = ip + tamanhoCabecalhoIp;

        // Camada de transporte: TCP ou ICMP.
        if (protocolo == PROTOCOLO_TCP && fim - transporte >= 14) {
            int portaOrigem = numero16(dados, transporte);
            int portaDestino = numero16(dados, transporte + 2);
            int flags = dados[transporte + 13] & 0xFF;
            // Pedido de conexão = SYN sem ACK (o SYN+ACK é a resposta do servidor).
            boolean syn = (flags & FLAG_SYN) != 0 && (flags & FLAG_ACK) == 0;
            return new PacoteTcp(instanteMs, origem, destino, tamanho, portaOrigem, portaDestino, syn);
        }
        if (protocolo == PROTOCOLO_ICMP && fim - transporte >= 1) {
            return new PacoteIcmp(instanteMs, origem, destino, tamanho, dados[transporte] & 0xFF);
        }
        return null;
    }

    /** Lê 2 bytes como um número sem sinal (os protocolos de rede usam a ordem "big-endian"). */
    private static int numero16(byte[] dados, int posicao) {
        return ((dados[posicao] & 0xFF) << 8) | (dados[posicao + 1] & 0xFF);
    }

    /** Converte 4 bytes no texto de um endereço IPv4, como "192.168.0.1". */
    private static String enderecoIp(byte[] dados, int posicao) {
        return (dados[posicao] & 0xFF) + "." + (dados[posicao + 1] & 0xFF) + "."
                + (dados[posicao + 2] & 0xFF) + "." + (dados[posicao + 3] & 0xFF);
    }
}
