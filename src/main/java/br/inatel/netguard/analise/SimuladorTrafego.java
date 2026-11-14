package br.inatel.netguard.analise;

import br.inatel.netguard.modelo.PacoteIcmp;
import br.inatel.netguard.modelo.PacoteRede;
import br.inatel.netguard.modelo.PacoteTcp;
import br.inatel.netguard.modelo.Servidor;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

// Gera tráfego falso para os servidores de uma empresa: acessos normais com
// quatro ataques no meio. Serve para testar sem precisar de uma rede real.
public class SimuladorTrafego implements FonteDeTrafego {

    private final List<Servidor> servidores;
    private final int totalPacotes;
    private final Random aleatorio = new Random(42); // semente fixa: sempre gera o mesmo tráfego
    private final List<PacoteRede> pacotes = new ArrayList<>();
    private long relogioMs = System.currentTimeMillis();

    public SimuladorTrafego(List<Servidor> servidores, int totalPacotes) {
        if (servidores == null || servidores.isEmpty()) {
            throw new IllegalArgumentException("a empresa precisa ter pelo menos um servidor cadastrado");
        }
        if (totalPacotes < 2000) {
            throw new IllegalArgumentException("a simulação precisa de pelo menos 2000 pacotes");
        }
        this.servidores = new ArrayList<>(servidores);
        this.totalPacotes = totalPacotes;
    }

    // sem throws: simular não dá erro
    @Override
    public List<PacoteRede> obterPacotes() {
        pacotes.clear();
        while (pacotes.size() < totalPacotes) {
            int posicao = pacotes.size();
            if (posicao == totalPacotes * 15 / 100) {
                injetarSynFlood();
            } else if (posicao == totalPacotes * 35 / 100) {
                injetarPortScan();
            } else if (posicao == totalPacotes * 50 / 100) {
                injetarPortasSuspeitas();
            } else if (posicao == totalPacotes * 80 / 100) {
                injetarPacotesGigantes();
            } else {
                gerarPacoteNormal();
            }
        }
        return new ArrayList<>(pacotes);
    }

    @Override
    public String descrever() {
        return "tráfego simulado para " + servidores.size() + " servidor(es)";
    }

    // 600 SYN em pouco mais de 1 segundo contra o primeiro servidor
    private void injetarSynFlood() {
        String alvo = servidores.get(0).getIp();
        for (int i = 0; i < 600; i++) {
            relogioMs += 2;
            pacotes.add(new PacoteTcp(relogioMs, "203.0.113.66", alvo, 60, portaAleatoria(), 80, true));
        }
    }

    // 150 portas diferentes, uma a cada 20 ms (devagar, para não virar SYN Flood)
    private void injetarPortScan() {
        String alvo = servidores.get(servidores.size() > 1 ? 1 : 0).getIp();
        for (int porta = 1000; porta < 1150; porta++) {
            relogioMs += 20;
            pacotes.add(new PacoteTcp(relogioMs, "203.0.113.200", alvo, 60, 61000, porta, true));
        }
    }

    // acesso às portas 4444 (shell remoto) e 23 (Telnet)
    private void injetarPortasSuspeitas() {
        String alvo = servidores.get(servidores.size() - 1).getIp();
        for (int i = 0; i < 5; i++) {
            relogioMs += 40;
            pacotes.add(new PacoteTcp(relogioMs, "192.168.1.37", alvo, 120, portaAleatoria(), 4444, i == 0));
        }
        relogioMs += 25;
        pacotes.add(new PacoteTcp(relogioMs, "198.51.100.23", alvo, 60, portaAleatoria(), 23, true));
    }

    // um ping gigante e um pacote TCP muito grande
    private void injetarPacotesGigantes() {
        relogioMs += 10;
        pacotes.add(new PacoteIcmp(relogioMs, "203.0.113.150", servidores.get(0).getIp(), 65000,
                PacoteIcmp.TIPO_ECHO_REQUEST));
        relogioMs += 10;
        String alvo = servidores.get(servidores.size() > 1 ? 1 : 0).getIp();
        pacotes.add(new PacoteTcp(relogioMs, "192.168.1.51", alvo, 9000, portaAleatoria(), 443, false));
    }

    private void gerarPacoteNormal() {
        relogioMs += 1 + aleatorio.nextInt(8);
        String cliente = "192.168.1." + (10 + aleatorio.nextInt(50));
        String servidor = servidores.get(aleatorio.nextInt(servidores.size())).getIp();

        if (aleatorio.nextInt(100) < 90) {
            // acesso web; às vezes abre conexão nova (SYN)
            boolean novaConexao = aleatorio.nextInt(100) < 8;
            int tamanho = novaConexao ? 60 : 40 + aleatorio.nextInt(1421);
            int porta = aleatorio.nextBoolean() ? 443 : 80;
            pacotes.add(new PacoteTcp(relogioMs, cliente, servidor, tamanho, portaAleatoria(), porta, novaConexao));
        } else {
            pacotes.add(new PacoteIcmp(relogioMs, cliente, servidor, 64, PacoteIcmp.TIPO_ECHO_REQUEST));
        }
    }

    private int portaAleatoria() {
        return 49152 + aleatorio.nextInt(16000);
    }
}
