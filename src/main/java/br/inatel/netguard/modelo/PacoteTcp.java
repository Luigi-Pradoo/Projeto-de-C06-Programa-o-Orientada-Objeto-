package br.inatel.netguard.modelo;

// Pacote TCP: tem portas e a flag SYN (pedido de conexão).
public class PacoteTcp extends PacoteRede {

    private final int portaOrigem;
    private final int portaDestino;
    private final boolean syn;

    public PacoteTcp(long instanteMs, String ipOrigem, String ipDestino, int tamanhoBytes,
                     int portaOrigem, int portaDestino, boolean syn) {
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
