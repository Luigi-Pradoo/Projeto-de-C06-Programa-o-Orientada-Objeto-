package br.inatel.netguard.analise;

import br.inatel.netguard.excecao.NetGuardException;
import br.inatel.netguard.modelo.Anomalia;

// Qualquer lugar para onde um alerta pode ir (tela, banco...).
public interface Notificador {

    void notificar(Anomalia anomalia) throws NetGuardException;
}
