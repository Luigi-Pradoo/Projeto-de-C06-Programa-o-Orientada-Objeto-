package br.inatel.netguard.analise;

import br.inatel.netguard.detector.Detector;
import br.inatel.netguard.excecao.NetGuardException;
import br.inatel.netguard.modelo.Anomalia;
import br.inatel.netguard.modelo.PacoteRede;

import java.util.ArrayList;
import java.util.List;

// Passa cada pacote por todos os detectores e manda os alertas para os notificadores.
// Só conhece Detector e Notificador, não sabe quais são as classes de verdade.
public class MotorDeteccao {

    private final List<Detector> detectores;
    private final List<Notificador> notificadores = new ArrayList<>();
    private final List<Anomalia> anomalias = new ArrayList<>();
    private int falhasDeNotificacao;

    public MotorDeteccao(List<Detector> detectores) {
        if (detectores == null || detectores.isEmpty()) {
            throw new IllegalArgumentException("o motor precisa de pelo menos um detector");
        }
        this.detectores = new ArrayList<>(detectores);
    }

    public void adicionarNotificador(Notificador notificador) {
        notificadores.add(notificador);
    }

    public void executar(List<PacoteRede> pacotes) {
        for (PacoteRede pacote : pacotes) {
            for (Detector detector : detectores) {
                // polimorfismo: cada detector roda a sua própria regra
                Anomalia resultado = detector.analisar(pacote);
                if (resultado != null) {
                    registrar(resultado);
                }
            }
        }
    }

    private void registrar(Anomalia anomalia) {
        anomalias.add(anomalia);
        for (Notificador notificador : notificadores) {
            // try dentro do for: se o banco falhar, a tela ainda recebe o alerta
            try {
                notificador.notificar(anomalia);
            } catch (NetGuardException e) {
                falhasDeNotificacao++;
                System.out.println("[ERRO] " + e.getMessage());
            }
        }
    }

    public List<Anomalia> getAnomalias() {
        return new ArrayList<>(anomalias);
    }

    public int getFalhasDeNotificacao() {
        return falhasDeNotificacao;
    }
}
