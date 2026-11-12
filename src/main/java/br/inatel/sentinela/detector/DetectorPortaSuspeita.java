package br.inatel.sentinela.detector;

import br.inatel.sentinela.modelo.Anomalia;
import br.inatel.sentinela.modelo.PacoteRede;
import br.inatel.sentinela.modelo.PacoteTcp;
import br.inatel.sentinela.modelo.Severidade;

import java.util.Map;
import java.util.Optional;

/**
 * Detecta tráfego para portas conhecidas por uso inseguro ou malicioso.
 * Um único pacote já basta para alertar: não precisa de janela de tempo.
 */
public class DetectorPortaSuspeita extends Detector {

    /** Tabela porta -> motivo da suspeita. Map.of cria um mapa que não pode ser alterado. */
    private static final Map<Integer, String> PORTAS_SUSPEITAS = Map.of(
            23, "Telnet (acesso remoto sem criptografia)",
            4444, "porta padrão de shell remoto do Metasploit",
            6667, "IRC (canal comum de comando de botnets)",
            31337, "porta clássica de backdoor (Back Orifice)");

    public DetectorPortaSuspeita() {
        super("Porta suspeita", Severidade.ALTA);
    }

    @Override
    protected boolean aceita(PacoteRede pacote) {
        return pacote instanceof PacoteTcp;
    }

    @Override
    protected Optional<Anomalia> inspecionar(PacoteRede pacote) {
        PacoteTcp tcp = (PacoteTcp) pacote;
        String motivo = PORTAS_SUSPEITAS.get(tcp.getPortaDestino());
        String chave = tcp.getIpOrigem() + "->" + tcp.getIpDestino() + ":" + tcp.getPortaDestino();
        if (motivo == null || !primeiraVez(chave)) {
            return Optional.empty();
        }
        String descricao = "tráfego para " + tcp.getIpDestino() + ":" + tcp.getPortaDestino() + ", " + motivo;
        return Optional.of(novaAnomalia(tcp, descricao));
    }
}
