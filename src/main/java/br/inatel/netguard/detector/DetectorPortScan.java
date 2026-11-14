package br.inatel.netguard.detector;

import br.inatel.netguard.modelo.Anomalia;
import br.inatel.netguard.modelo.PacoteRede;
import br.inatel.netguard.modelo.PacoteTcp;
import br.inatel.netguard.modelo.Severidade;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

// Port Scan: o mesmo IP testando muitas portas diferentes de um servidor em pouco tempo.
// (o SYN Flood olha a quantidade de pedidos; aqui o que importa é a variedade de portas)
public class DetectorPortScan extends Detector {

    private final long janelaMs;
    private final int limitePortas;
    // "origem -> destino" -> (porta -> último instante em que foi testada)
    private final Map<String, Map<Integer, Long>> portasPorPar = new HashMap<>();

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
    protected Anomalia inspecionar(PacoteRede pacote) {
        PacoteTcp tcp = (PacoteTcp) pacote;
        if (!tcp.isSyn()) {
            return null;
        }
        String par = tcp.getIpOrigem() + " -> " + tcp.getIpDestino();
        Map<Integer, Long> portas = portasPorPar.get(par);
        if (portas == null) {
            portas = new HashMap<>();
            portasPorPar.put(par, portas);
        }
        portas.put(tcp.getPortaDestino(), tcp.getInstanteMs());

        // remove as portas antigas; tem que ser pelo Iterator para não dar erro no meio do laço
        long agora = tcp.getInstanteMs();
        Iterator<Long> iterador = portas.values().iterator();
        while (iterador.hasNext()) {
            long instante = iterador.next();
            if (agora - instante > janelaMs) {
                iterador.remove();
            }
        }

        if (portas.size() > limitePortas && primeiraVez(par)) {
            String descricao = portas.size() + " portas diferentes testadas em " + tcp.getIpDestino()
                    + " em até " + janelaMs + " ms (limite: " + limitePortas + ")";
            return novaAnomalia(tcp, descricao);
        }
        return null;
    }
}
