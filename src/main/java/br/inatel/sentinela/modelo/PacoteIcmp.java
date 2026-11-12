package br.inatel.sentinela.modelo;

/**
 * Pacote ICMP, o protocolo de mensagens de controle (é o que o comando "ping" usa).
 *
 * ICMP não tem portas. No lugar delas existe um "tipo" de mensagem:
 * 8 é o pedido de eco ("tem alguém aí?") e 0 é a resposta.
 */
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
