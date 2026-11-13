package br.inatel.netguard.modelo;

/**
 * Representa um pacote de dados que trafegou pela rede.
 *
 * É uma classe ABSTRATA porque "pacote de rede" sozinho é uma ideia genérica:
 * na prática todo pacote é de algum protocolo (TCP, ICMP...). Aqui fica tudo
 * o que é comum a qualquer pacote; o que muda de um protocolo para o outro é
 * deixado como método abstrato para as subclasses resolverem.
 */
public abstract class PacoteRede {

    private final long instanteMs;
    private final String ipOrigem;
    private final String ipDestino;
    private final int tamanhoBytes;

    /**
     * Construtor protegido: só as subclasses podem chamar (com super(...)).
     * Toda validação comum fica aqui, então nenhum pacote inválido chega a existir.
     *
     * @throws IllegalArgumentException se algum dado for inválido
     */
    protected PacoteRede(long instanteMs, String ipOrigem, String ipDestino, int tamanhoBytes) {
        if (!ehIpv4Valido(ipOrigem) || !ehIpv4Valido(ipDestino)) {
            throw new IllegalArgumentException("IP inválido: " + ipOrigem + " -> " + ipDestino);
        }
        if (tamanhoBytes <= 0) {
            throw new IllegalArgumentException("tamanho deve ser positivo: " + tamanhoBytes);
        }
        this.instanteMs = instanteMs;
        this.ipOrigem = ipOrigem;
        this.ipDestino = ipDestino;
        this.tamanhoBytes = tamanhoBytes;
    }

    // ---------- o que cada protocolo define do seu jeito ----------

    /** @return o nome do protocolo deste pacote ("TCP" ou "ICMP") */
    public abstract String getProtocolo();

    /** @return uma frase curta descrevendo o pacote, usada nos alertas */
    public abstract String descrever();

    // ---------- o que é igual para todo pacote ----------

    public long getInstanteMs() {
        return instanteMs;
    }

    public String getIpOrigem() {
        return ipOrigem;
    }

    public String getIpDestino() {
        return ipDestino;
    }

    public int getTamanhoBytes() {
        return tamanhoBytes;
    }

    @Override
    public String toString() {
        return descrever();
    }

    /**
     * Confere se o texto tem o formato de um endereço IPv4 (ex.: 192.168.1.10).
     * É static porque não depende de nenhum pacote: a classe Servidor também usa.
     */
    public static boolean ehIpv4Valido(String ip) {
        if (ip == null) {
            return false;
        }
        // O -1 faz o split manter partes vazias no fim: "10.0.0.1." vira 5 partes e é recusado.
        String[] partes = ip.trim().split("\\.", -1);
        if (partes.length != 4) {
            return false;
        }
        for (String parte : partes) {
            // Só aceita de 1 a 3 algarismos: recusa "", "+1", "-0" e letras antes de converter.
            if (!parte.matches("[0-9]{1,3}") || Integer.parseInt(parte) > 255) {
                return false;
            }
        }
        return true;
    }
}
