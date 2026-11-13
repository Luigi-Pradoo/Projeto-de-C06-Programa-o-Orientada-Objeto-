package br.inatel.netguard.analise;

import br.inatel.netguard.modelo.Anomalia;

/**
 * Mostra cada alerta na tela, no momento em que a anomalia é detectada.
 */
public class NotificadorConsole implements Notificador {

    @Override
    public void notificar(Anomalia anomalia) {
        // Não declara "throws": escrever na tela não falha, e uma implementação
        // pode lançar MENOS exceções do que a interface permite.
        System.out.println("[ALERTA] " + anomalia);
    }
}
