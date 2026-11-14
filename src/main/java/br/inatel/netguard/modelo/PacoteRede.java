package br.inatel.netguard.modelo;

// Classe mãe de todos os pacotes. É abstrata porque todo pacote é de algum
// protocolo (TCP ou ICMP); aqui fica só o que é comum a todos.
public abstract class PacoteRede {

    private final long instanteMs;
    private final String ipOrigem;
    private final String ipDestino;
    private final int tamanhoBytes;

    // protected: só as subclasses chamam, com super(...)
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

    // cada protocolo implementa do seu jeito
    public abstract String getProtocolo();

    public abstract String descrever();

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

    // static porque não depende de um pacote; o Servidor também usa
    public static boolean ehIpv4Valido(String ip) {
        if (ip == null) {
            return false;
        }
        // o -1 mantém partes vazias, então "10.0.0.1." é recusado
        String[] partes = ip.trim().split("\\.", -1);
        if (partes.length != 4) {
            return false;
        }
        for (String parte : partes) {
            if (!parte.matches("[0-9]{1,3}") || Integer.parseInt(parte) > 255) {
                return false;
            }
        }
        return true;
    }
}
