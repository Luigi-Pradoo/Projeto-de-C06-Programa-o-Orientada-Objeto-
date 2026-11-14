package br.inatel.netguard.detector;

import br.inatel.netguard.modelo.Anomalia;
import br.inatel.netguard.modelo.PacoteRede;
import br.inatel.netguard.modelo.Severidade;

// Pacote maior que o normal da rede (1500 bytes no Ethernet), como o "ping da morte".
// Vale para TCP e ICMP, então não sobrescreve o aceita().
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
    protected Anomalia inspecionar(PacoteRede pacote) {
        if (pacote.getTamanhoBytes() <= limiteBytes || !primeiraVez(pacote.getIpOrigem())) {
            return null;
        }
        // descrever() muda conforme o tipo do pacote (polimorfismo)
        String descricao = "pacote " + pacote.getProtocolo() + " acima de " + limiteBytes + " bytes: "
                + pacote.descrever();
        return novaAnomalia(pacote, descricao);
    }
}
