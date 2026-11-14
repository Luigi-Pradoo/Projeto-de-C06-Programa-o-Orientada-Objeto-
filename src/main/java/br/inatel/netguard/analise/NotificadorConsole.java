package br.inatel.netguard.analise;

import br.inatel.netguard.modelo.Anomalia;

// Mostra o alerta na tela.
public class NotificadorConsole implements Notificador {

    // não precisa de throws: escrever na tela não falha
    @Override
    public void notificar(Anomalia anomalia) {
        System.out.println("[ALERTA] " + anomalia);
    }
}
