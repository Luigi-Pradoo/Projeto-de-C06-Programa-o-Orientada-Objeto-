package br.inatel.netguard.detector;

import br.inatel.netguard.modelo.Anomalia;
import br.inatel.netguard.modelo.PacoteRede;
import br.inatel.netguard.modelo.PacoteTcp;
import br.inatel.netguard.modelo.Severidade;

import java.util.HashMap;
import java.util.Map;

// Acesso a portas conhecidas por serem usadas em ataques. Um pacote já basta.
public class DetectorPortaSuspeita extends Detector {

    // porta -> motivo
    private final Map<Integer, String> portasSuspeitas = new HashMap<>();

    public DetectorPortaSuspeita() {
        super("Porta suspeita", Severidade.ALTA);
        portasSuspeitas.put(23, "Telnet (acesso remoto sem criptografia)");
        portasSuspeitas.put(4444, "porta padrão de shell remoto do Metasploit");
        portasSuspeitas.put(6667, "IRC (canal comum de comando de botnets)");
        portasSuspeitas.put(31337, "porta clássica de backdoor (Back Orifice)");
    }

    @Override
    protected boolean aceita(PacoteRede pacote) {
        return pacote instanceof PacoteTcp;
    }

    @Override
    protected Anomalia inspecionar(PacoteRede pacote) {
        PacoteTcp tcp = (PacoteTcp) pacote;
        String motivo = portasSuspeitas.get(tcp.getPortaDestino());
        String chave = tcp.getIpOrigem() + "->" + tcp.getIpDestino() + ":" + tcp.getPortaDestino();
        if (motivo == null || !primeiraVez(chave)) {
            return null;
        }
        String descricao = "tráfego para " + tcp.getIpDestino() + ":" + tcp.getPortaDestino() + ", " + motivo;
        return novaAnomalia(tcp, descricao);
    }
}
