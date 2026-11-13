package br.inatel.netguard.analise;

import br.inatel.netguard.excecao.NetGuardException;
import br.inatel.netguard.modelo.PacoteRede;

import java.util.List;

/**
 * Contrato de qualquer lugar de onde vem o tráfego a ser analisado.
 *
 * Hoje há duas implementações: SimuladorTrafego (tráfego inventado) e
 * LeitorPcap (tráfego real, gravado pelo Wireshark). O motor e o menu só
 * conhecem este tipo, então trocar de fonte não muda nada na análise.
 */
public interface FonteDeTrafego {

    /**
     * @return os pacotes, na ordem em que chegaram
     * @throws NetGuardException se não for possível obter o tráfego (por exemplo, arquivo inválido)
     */
    List<PacoteRede> obterPacotes() throws NetGuardException;

    /** @return uma frase curta dizendo de onde veio o tráfego, para mostrar na tela */
    String descrever();
}
