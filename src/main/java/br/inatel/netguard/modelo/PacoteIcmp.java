package br.inatel.netguard.modelo;

// Pacote ICMP (o do ping). Não tem porta, tem um tipo: 8 = pedido, 0 = resposta.
public class PacoteIcmp extends PacoteRede {

    public static final int TIPO_ECHO_REPLY = 0;
    public static final int TIPO_ECHO_REQUEST = 8;

    private final int tipo;

    public PacoteIcmp(long instanteMs, String ipOrigem, String ipDestino, int tamanhoBytes, int tipo) {
        super(instanteMs, ipOrigem, ipDestino, tamanhoBytes);
        this.tipo = tipo;
    }

    public int getTipo() {
        return tipo;
    }

    @Override
    public String getProtocolo() {
        return "ICMP";
    }

    @Override
    public String descrever() {
        return "ICMP " + getIpOrigem() + " -> " + getIpDestino() + " [tipo " + tipo + "] "
                + getTamanhoBytes() + " bytes";
    }
}
