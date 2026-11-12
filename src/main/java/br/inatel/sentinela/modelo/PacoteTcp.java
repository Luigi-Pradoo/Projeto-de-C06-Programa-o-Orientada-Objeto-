package br.inatel.sentinela.modelo;

/**
 * Pacote TCP: além do que todo pacote tem, guarda as portas de origem e de
 * destino e a flag SYN, que indica um pedido de abertura de conexão.
 */
public class PacoteTcp extends PacoteRede {

    private final int portaOrigem;
    private final int portaDestino;
    private final boolean syn;

    public PacoteTcp(long instanteMs, String ipOrigem, String ipDestino, int tamanhoBytes,
                     int portaOrigem, int portaDestino, boolean syn) {
        // super(...) chama o construtor de PacoteRede, que valida e guarda a parte comum.
        super(instanteMs, ipOrigem, ipDestino, tamanhoBytes);
        if (portaOrigem < 0 || portaOrigem > 65535 || portaDestino < 0 || portaDestino > 65535) {
            throw new IllegalArgumentException("porta fora da faixa 0-65535");
        }
        this.portaOrigem = portaOrigem;
        this.portaDestino = portaDestino;
        this.syn = syn;
    }

    public int getPortaOrigem() {
        return portaOrigem;
    }

    public int getPortaDestino() {
        return portaDestino;
    }

    /** SYN ligado: alguém está pedindo para abrir uma conexão nova. */
    public boolean isSyn() {
        return syn;
    }

    @Override
    public String getProtocolo() {
        return "TCP";
    }

    @Override
    public String descrever() {
        return "TCP " + getIpOrigem() + ":" + portaOrigem + " -> " + getIpDestino() + ":" + portaDestino
                + (syn ? " [SYN]" : "") + " " + getTamanhoBytes() + " bytes";
    }
}
