package br.inatel.netguard.analise;

import br.inatel.netguard.excecao.NetGuardException;
import br.inatel.netguard.modelo.PacoteIcmp;
import br.inatel.netguard.modelo.PacoteRede;
import br.inatel.netguard.modelo.PacoteTcp;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

// Lê um arquivo .pcap salvo pelo Wireshark e transforma em PacoteTcp e PacoteIcmp.
// Formato: cabeçalho do arquivo (24 bytes) e depois, para cada pacote,
// 16 bytes de cabeçalho + os bytes do pacote (Ethernet -> IPv4 -> TCP/ICMP).
public class LeitorPcap implements FonteDeTrafego {

    private static final int MAGICO_MICROSSEGUNDOS = 0xA1B2C3D4;
    private static final int MAGICO_NANOSSEGUNDOS = 0xA1B23C4D;
    private static final int MAGICO_PCAPNG = 0x0A0D0D0A;
    private static final int ENLACE_ETHERNET = 1;
    private static final int ETHERTYPE_IPV4 = 0x0800;
    private static final int PROTOCOLO_ICMP = 1;
    private static final int PROTOCOLO_TCP = 6;

    private final Path arquivo;
    private int pacotesIgnorados;

    public LeitorPcap(Path arquivo) {
        if (arquivo == null) {
            throw new IllegalArgumentException("informe o caminho do arquivo de captura");
        }
        this.arquivo = arquivo;
    }

    @Override
    public List<PacoteRede> obterPacotes() throws NetGuardException {
        byte[] dados;
        try {
            dados = Files.readAllBytes(arquivo);
        } catch (NoSuchFileException e) {
            throw new NetGuardException("arquivo não encontrado: " + arquivo.toAbsolutePath());
        } catch (IOException e) {
            throw new NetGuardException("não foi possível ler o arquivo " + arquivo, e);
        }
        if (dados.length < 24) {
            throw new NetGuardException("o arquivo é pequeno demais para ser uma captura pcap");
        }

        // cabeçalho do arquivo: o número mágico diz o formato e a ordem dos bytes
        ByteBuffer buffer = ByteBuffer.wrap(dados);
        int magico = buffer.getInt(0);
        if (magico == MAGICO_PCAPNG) {
            throw new NetGuardException("o arquivo está no formato pcapng. No Wireshark, use"
                    + " Arquivo > Salvar como e escolha \"Wireshark/tcpdump/... - pcap\"");
        }
        if (magico != MAGICO_MICROSSEGUNDOS && magico != MAGICO_NANOSSEGUNDOS) {
            buffer.order(ByteOrder.LITTLE_ENDIAN); // no Windows os bytes vêm invertidos
            magico = buffer.getInt(0);
        }
        if (magico != MAGICO_MICROSSEGUNDOS && magico != MAGICO_NANOSSEGUNDOS) {
            throw new NetGuardException("o arquivo não é uma captura pcap: " + arquivo.getFileName());
        }
        if (buffer.getInt(20) != ENLACE_ETHERNET) {
            throw new NetGuardException("só são aceitas capturas de rede Ethernet ou Wi-Fi");
        }
        boolean nanossegundos = magico == MAGICO_NANOSSEGUNDOS;

        // um registro por pacote até o fim do arquivo
        List<PacoteRede> pacotes = new ArrayList<>();
        pacotesIgnorados = 0;
        buffer.position(24);
        while (buffer.remaining() >= 16) {
            long segundos = buffer.getInt() & 0xFFFFFFFFL;
            long fracao = buffer.getInt() & 0xFFFFFFFFL;
            int bytesGravados = buffer.getInt();
            buffer.getInt(); // tamanho original, não usado
            if (bytesGravados < 0 || bytesGravados > buffer.remaining()) {
                break; // arquivo cortado no meio
            }
            int inicio = buffer.position();
            buffer.position(inicio + bytesGravados);

            long instanteMs = segundos * 1000 + (nanossegundos ? fracao / 1_000_000 : fracao / 1000);
            PacoteRede pacote = decodificar(dados, inicio, inicio + bytesGravados, instanteMs);
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

    // devolve null se o pacote não for IPv4 com TCP ou ICMP
    private PacoteRede decodificar(byte[] dados, int inicio, int fim, long instanteMs) {
        // Ethernet: 14 bytes, o tipo fica nos bytes 12 e 13
        if (fim - inicio < 14 || numero16(dados, inicio + 12) != ETHERTYPE_IPV4) {
            return null;
        }
        int ip = inicio + 14;

        // IPv4
        if (fim - ip < 20 || (dados[ip] & 0xFF) >> 4 != 4) {
            return null;
        }
        int tamanhoCabecalhoIp = (dados[ip] & 0x0F) * 4;
        // tamanho do pacote IP (é o que se compara com o limite de 1500 bytes).
        // algumas placas gravam 0 aqui; nesse caso usa o que foi gravado no arquivo
        int tamanho = numero16(dados, ip + 2);
        if (tamanho == 0) {
            tamanho = fim - ip;
        }
        if ((numero16(dados, ip + 6) & 0x1FFF) != 0) {
            return null; // pedaço de pacote fragmentado, sem cabeçalho TCP/ICMP
        }
        int protocolo = dados[ip + 9] & 0xFF;
        String origem = enderecoIp(dados, ip + 12);
        String destino = enderecoIp(dados, ip + 16);
        int transporte = ip + tamanhoCabecalhoIp;

        // TCP ou ICMP
        if (protocolo == PROTOCOLO_TCP && fim - transporte >= 14) {
            int portaOrigem = numero16(dados, transporte);
            int portaDestino = numero16(dados, transporte + 2);
            int flags = dados[transporte + 13] & 0xFF;
            boolean syn = (flags & 0x02) != 0 && (flags & 0x10) == 0; // SYN sem ACK = pedido de conexão
            return new PacoteTcp(instanteMs, origem, destino, tamanho, portaOrigem, portaDestino, syn);
        }
        if (protocolo == PROTOCOLO_ICMP && fim - transporte >= 1) {
            return new PacoteIcmp(instanteMs, origem, destino, tamanho, dados[transporte] & 0xFF);
        }
        return null;
    }

    // lê 2 bytes como número (na rede o byte mais alto vem primeiro)
    private static int numero16(byte[] dados, int posicao) {
        return ((dados[posicao] & 0xFF) << 8) | (dados[posicao + 1] & 0xFF);
    }

    private static String enderecoIp(byte[] dados, int posicao) {
        return (dados[posicao] & 0xFF) + "." + (dados[posicao + 1] & 0xFF) + "."
                + (dados[posicao + 2] & 0xFF) + "." + (dados[posicao + 3] & 0xFF);
    }
}
