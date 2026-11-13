package br.inatel.netguard.analise;

import br.inatel.netguard.excecao.NetGuardException;
import br.inatel.netguard.modelo.Anomalia;

/**
 * Contrato de qualquer destino para onde um alerta pode ir.
 *
 * Hoje existem dois: a tela (NotificadorConsole) e o banco de dados
 * (BancoDeDados). Um destino novo, como e-mail, seria só mais uma classe
 * implementando esta interface.
 */
public interface Notificador {

    /**
     * Entrega o alerta pelo canal deste notificador.
     *
     * @throws NetGuardException se o canal falhar
     */
    void notificar(Anomalia anomalia) throws NetGuardException;
}
