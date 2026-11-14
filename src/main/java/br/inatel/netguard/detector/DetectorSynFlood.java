package br.inatel.netguard.detector;

import br.inatel.netguard.modelo.Anomalia;
import br.inatel.netguard.modelo.PacoteRede;
import br.inatel.netguard.modelo.PacoteTcp;
import br.inatel.netguard.modelo.Severidade;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

// SYN Flood: o mesmo IP pedindo conexão (SYN) muitas vezes em pouco tempo.
public class DetectorSynFlood extends Detector {

    private final long janelaMs;
    private final int limite;
    // IP de origem -> instantes dos SYN recentes
    private final Map<String, List<Long>> synPorOrigem = new HashMap<>();

    public DetectorSynFlood(long janelaMs, int limite) {
        super("SYN Flood", Severidade.CRITICA);
        if (janelaMs <= 0 || limite <= 0) {
            throw new IllegalArgumentException("janela e limite precisam ser positivos");
        }
        this.janelaMs = janelaMs;
        this.limite = limite;
    }

    // só olha pacotes TCP
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

        // tira do começo da lista os SYN que já saíram da janela
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
