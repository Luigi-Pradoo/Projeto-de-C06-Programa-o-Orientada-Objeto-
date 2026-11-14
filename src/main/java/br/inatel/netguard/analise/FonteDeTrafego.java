package br.inatel.netguard.analise;

import br.inatel.netguard.excecao.NetGuardException;
import br.inatel.netguard.modelo.PacoteRede;

import java.util.List;

// De onde vem o tráfego: simulado ou lido de um arquivo .pcap.
public interface FonteDeTrafego {

    List<PacoteRede> obterPacotes() throws NetGuardException;

    String descrever();
}
