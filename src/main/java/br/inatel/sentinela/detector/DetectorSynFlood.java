package br.inatel.sentinela.detector;

import br.inatel.sentinela.modelo.Anomalia;
import br.inatel.sentinela.modelo.PacoteRede;
import br.inatel.sentinela.modelo.PacoteTcp;
import br.inatel.sentinela.modelo.Severidade;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Detecta SYN Flood: um mesmo IP pedindo conexões TCP (SYN) em ritmo muito
 * acima do normal, para esgotar os recursos do servidor.
 *
 * Um SYN sozinho é normal; o problema é a quantidade dentro de uma janela de
 * tempo. Por isso o detector guarda, para cada IP de origem, os instantes dos
 * SYN recentes e conta quantos caíram na janela.
 */
public class DetectorSynFlood extends Detector {

    private final long janelaMs;
    private final int limite;
    private final Map<String, List<Long>> synPorOrigem = new HashMap<>();

    /**
     * @param janelaMs tamanho da janela de tempo, em milissegundos
     * @param limite   quantidade de SYN na janela a partir da qual é ataque
     */
    public DetectorSynFlood(long janelaMs, int limite) {
        super("SYN Flood", Severidade.CRITICA);
        if (janelaMs <= 0 || limite <= 0) {
            throw new IllegalArgumentException("janela e limite precisam ser positivos");
        }
        this.janelaMs = janelaMs;
        this.limite = limite;
    }

    @Override
    protected boolean aceita(PacoteRede pacote) {
        return pacote instanceof PacoteTcp;
    }

    @Override
    protected Anomalia inspecionar(PacoteRede pacote) {
        PacoteTcp tcp = (PacoteTcp) pacote;
        if (!tcp.isSyn()) {
            return null;
        }
        String origem = tcp.getIpOrigem();
        List<Long> instantes = synPorOrigem.get(origem);
        if (instantes == null) {
            instantes = new ArrayList<>();
            synPorOrigem.put(origem, instantes);
        }
        instantes.add(tcp.getInstanteMs());
        // Os instantes ficam em ordem de chegada: o mais velho está na posição 0.
        // Remove do começo da lista os SYN mais velhos que a janela.
        while (tcp.getInstanteMs() - instantes.get(0) > janelaMs) {
            instantes.remove(0);
        }
        if (instantes.size() > limite && primeiraVez(origem)) {
            String descricao = instantes.size() + " pedidos de conexão em " + janelaMs + " ms contra "
                    + tcp.getIpDestino() + ":" + tcp.getPortaDestino() + " (limite: " + limite + ")";
            return novaAnomalia(tcp, descricao);
        }
        return null;
    }
}
