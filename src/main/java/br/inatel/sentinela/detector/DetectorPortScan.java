package br.inatel.sentinela.detector;

import br.inatel.sentinela.modelo.Anomalia;
import br.inatel.sentinela.modelo.PacoteRede;
import br.inatel.sentinela.modelo.PacoteTcp;
import br.inatel.sentinela.modelo.Severidade;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Detecta Port Scan (varredura de portas): um mesmo IP tentando abrir conexão
 * em muitas portas DIFERENTES do mesmo servidor em pouco tempo. É o que
 * ferramentas como o nmap fazem para descobrir quais serviços estão abertos,
 * e costuma ser o primeiro passo de um ataque.
 *
 * A diferença para o SYN Flood: o SYN Flood olha a QUANTIDADE de pedidos;
 * o Port Scan olha a VARIEDADE de portas. Mil pedidos para a porta 80 não são
 * varredura; trinta pedidos para trinta portas diferentes são.
 */
public class DetectorPortScan extends Detector {

    private final long janelaMs;
    private final int limitePortas;

    /** Para cada par "origem -> destino": porta testada -> último instante em que foi testada. */
    private final Map<String, Map<Integer, Long>> portasPorPar = new HashMap<>();

    /**
     * @param janelaMs     tamanho da janela de tempo, em milissegundos
     * @param limitePortas quantidade de portas diferentes na janela a partir da qual é varredura
     */
    public DetectorPortScan(long janelaMs, int limitePortas) {
        super("Port Scan", Severidade.ALTA);
        if (janelaMs <= 0 || limitePortas <= 0) {
            throw new IllegalArgumentException("janela e limite precisam ser positivos");
        }
        this.janelaMs = janelaMs;
        this.limitePortas = limitePortas;
    }

    @Override
    protected boolean aceita(PacoteRede pacote) {
        return pacote instanceof PacoteTcp;
    }

    @Override
    protected Optional<Anomalia> inspecionar(PacoteRede pacote) {
        PacoteTcp tcp = (PacoteTcp) pacote;
        // Só pedidos de conexão contam: é assim que a varredura "bate" em cada porta.
        if (!tcp.isSyn()) {
            return Optional.empty();
        }
        String par = tcp.getIpOrigem() + " -> " + tcp.getIpDestino();
        Map<Integer, Long> portas = portasPorPar.get(par);
        if (portas == null) {
            portas = new HashMap<>();
            portasPorPar.put(par, portas);
        }
        portas.put(tcp.getPortaDestino(), tcp.getInstanteMs());

        // Esquece as portas testadas há mais tempo que a janela.
        long agora = tcp.getInstanteMs();
        portas.values().removeIf(instante -> agora - instante > janelaMs);

        if (portas.size() > limitePortas && primeiraVez(par)) {
            String descricao = portas.size() + " portas diferentes testadas em " + tcp.getIpDestino()
                    + " em até " + janelaMs + " ms (limite: " + limitePortas + ")";
            return Optional.of(novaAnomalia(tcp, descricao));
        }
        return Optional.empty();
    }
}
