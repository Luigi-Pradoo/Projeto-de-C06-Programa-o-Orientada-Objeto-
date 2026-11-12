package br.inatel.sentinela.analise;

import br.inatel.sentinela.detector.Detector;
import br.inatel.sentinela.excecao.SentinelaException;
import br.inatel.sentinela.modelo.Anomalia;
import br.inatel.sentinela.modelo.PacoteRede;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Coordena uma análise: passa cada pacote por todos os detectores e entrega
 * as anomalias encontradas a todos os notificadores.
 *
 * Só conhece os tipos gerais: Detector (classe abstrata) e Notificador
 * (interface). Acrescentar um detector ou um destino de alertas não exige
 * mudar nada aqui.
 */
public class MotorDeteccao {

    private final List<Detector> detectores;
    private final List<Notificador> notificadores = new ArrayList<>();
    private final List<Anomalia> anomalias = new ArrayList<>();
    private MonitorAoVivo monitor; // opcional: null quando o modo ao vivo está desligado

    /**
     * @throws IllegalArgumentException se a lista de detectores estiver vazia
     */
    public MotorDeteccao(List<Detector> detectores) {
        if (detectores == null || detectores.isEmpty()) {
            throw new IllegalArgumentException("o motor precisa de pelo menos um detector");
        }
        // Cópia defensiva: mudanças na lista original não afetam o motor.
        this.detectores = new ArrayList<>(detectores);
    }

    public void adicionarNotificador(Notificador notificador) {
        notificadores.add(notificador);
    }

    /** Liga o modo ao vivo. Sem monitor (o padrão), a análise roda em silêncio. */
    public void setMonitor(MonitorAoVivo monitor) {
        this.monitor = monitor;
    }

    /** Analisa todos os pacotes, um de cada vez. */
    public void executar(List<PacoteRede> pacotes) {
        if (monitor != null) {
            monitor.iniciar(pacotes.size());
        }
        int numero = 0;
        for (PacoteRede pacote : pacotes) {
            numero++;
            // Primeiro todos os detectores olham o pacote...
            List<Anomalia> doPacote = new ArrayList<>();
            for (Detector detector : detectores) {
                // POLIMORFISMO: a mesma chamada executa a regra de cada detector,
                // conforme o tipo real do objeto que está na lista.
                Optional<Anomalia> resultado = detector.analisar(pacote);
                if (resultado.isPresent()) {
                    doPacote.add(resultado.get());
                }
            }
            // ...depois o monitor mostra o pacote e, logo abaixo dele, saem os alertas.
            if (monitor != null) {
                monitor.pacoteAnalisado(numero, pacote, doPacote.size());
            }
            for (Anomalia anomalia : doPacote) {
                registrar(anomalia);
            }
        }
    }

    /**
     * Guarda a anomalia e avisa todos os notificadores.
     *
     * O try/catch fica DENTRO do laço: se um notificador falhar (o banco, por
     * exemplo), o erro é informado e os outros continuam sendo chamados.
     */
    private void registrar(Anomalia anomalia) {
        anomalias.add(anomalia);
        for (Notificador notificador : notificadores) {
            try {
                // POLIMORFISMO de novo: na tela imprime, no banco grava.
                notificador.notificar(anomalia);
            } catch (SentinelaException e) {
                System.out.println("[ERRO] " + e.getMessage());
            }
        }
    }

    /** @return uma CÓPIA da lista de anomalias, para ninguém alterar a lista interna por fora */
    public List<Anomalia> getAnomalias() {
        return new ArrayList<>(anomalias);
    }
}
