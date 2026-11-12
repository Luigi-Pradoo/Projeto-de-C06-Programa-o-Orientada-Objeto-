package br.inatel.sentinela.detector;

import br.inatel.sentinela.modelo.Anomalia;
import br.inatel.sentinela.modelo.PacoteRede;
import br.inatel.sentinela.modelo.Severidade;

import java.util.Optional;

/**
 * Detecta pacotes maiores que o tamanho máximo normal da rede (1500 bytes em
 * uma rede Ethernet). Pacotes gigantes indicam ataques como o "ping da morte".
 *
 * Vale para qualquer protocolo, então NÃO sobrescreve aceita(): usa o
 * comportamento herdado de Detector, que aceita todos os pacotes.
 */
public class DetectorTamanhoAnormal extends Detector {

    private final int limiteBytes;

    public DetectorTamanhoAnormal(int limiteBytes) {
        super("Tamanho anormal", Severidade.BAIXA);
        if (limiteBytes <= 0) {
            throw new IllegalArgumentException("o limite precisa ser positivo: " + limiteBytes);
        }
        this.limiteBytes = limiteBytes;
    }

    @Override
    protected Optional<Anomalia> inspecionar(PacoteRede pacote) {
        if (pacote.getTamanhoBytes() <= limiteBytes || !primeiraVez(pacote.getIpOrigem())) {
            return Optional.empty();
        }
        // descrever() é polimórfico: o texto depende do tipo real do pacote (TCP ou ICMP).
        String descricao = "pacote " + pacote.getProtocolo() + " acima de " + limiteBytes + " bytes: "
                + pacote.descrever();
        return Optional.of(novaAnomalia(pacote, descricao));
    }
}
