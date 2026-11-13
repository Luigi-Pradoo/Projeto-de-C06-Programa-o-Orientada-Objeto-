package br.inatel.netguard.analise;

import br.inatel.netguard.modelo.PacoteIcmp;
import br.inatel.netguard.modelo.PacoteRede;
import br.inatel.netguard.modelo.PacoteTcp;
import br.inatel.netguard.modelo.Servidor;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Inventa o tráfego que chega aos servidores de uma empresa: clientes
 * acessando os servidores e pings normais, com quatro ataques no meio.
 *
 * Existe para que o sistema possa ser demonstrado em qualquer computador,
 * sem precisar de permissão de administrador nem de uma rede sob ataque.
 * Usa uma semente fixa, então a mesma simulação se repete sempre igual.
 */
public class SimuladorTrafego implements FonteDeTrafego {

    public static final int TOTAL_MINIMO = 2000;

    private final List<Servidor> servidores;
    private final int totalPacotes;
    private final Random aleatorio = new Random(42);
    private final List<PacoteRede> pacotes = new ArrayList<>();

    /** Relógio da rede simulada: é ele que carimba o instante de cada pacote. */
    private long relogioMs = System.currentTimeMillis();

    /**
     * @throws IllegalArgumentException se não houver servidor ou se a quantidade for pequena demais
     */
    public SimuladorTrafego(List<Servidor> servidores, int totalPacotes) {
        if (servidores == null || servidores.isEmpty()) {
            throw new IllegalArgumentException("a empresa precisa ter pelo menos um servidor cadastrado");
        }
        if (totalPacotes < TOTAL_MINIMO) {
            throw new IllegalArgumentException(
                    "a simulação precisa de pelo menos " + TOTAL_MINIMO + " pacotes, recebido " + totalPacotes);
        }
        this.servidores = new ArrayList<>(servidores);
        this.totalPacotes = totalPacotes;
    }

    /**
     * @return a lista de pacotes simulados, na ordem em que "chegaram".
     *         Diferente da interface, não declara "throws": simular nunca falha,
     *         e uma implementação pode lançar menos exceções que o contrato.
     */
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

    // ------------------------------ ataques ------------------------------

    /** 600 pedidos de conexão em pouco mais de um segundo contra o primeiro servidor. */
    private void injetarSynFlood() {
        String alvo = servidores.get(0).getIp();
        for (int i = 0; i < 600; i++) {
            relogioMs += 2;
            pacotes.add(new PacoteTcp(relogioMs, "203.0.113.66", alvo, 60, portaAleatoria(), 80, true));
        }
    }

    /**
     * Uma varredura de portas no segundo servidor: 150 portas diferentes, uma a
     * cada 20 ms. O ritmo (50 por segundo) fica abaixo do limite do SYN Flood
     * de propósito: o que denuncia a varredura é a variedade de portas.
     */
    private void injetarPortScan() {
        String alvo = servidores.get(servidores.size() > 1 ? 1 : 0).getIp();
        for (int porta = 1000; porta < 1150; porta++) {
            relogioMs += 20;
            pacotes.add(new PacoteTcp(relogioMs, "203.0.113.200", alvo, 60, 61000, porta, true));
        }
    }

    /** Uma máquina tentando um shell remoto e outra usando Telnet no último servidor. */
    private void injetarPortasSuspeitas() {
        String alvo = servidores.get(servidores.size() - 1).getIp();
        for (int i = 0; i < 5; i++) {
            relogioMs += 40;
            pacotes.add(new PacoteTcp(relogioMs, "192.168.1.37", alvo, 120, portaAleatoria(), 4444, i == 0));
        }
        relogioMs += 25;
        pacotes.add(new PacoteTcp(relogioMs, "198.51.100.23", alvo, 60, portaAleatoria(), 23, true));
    }

    /** Um "ping da morte" (ICMP gigante) e um pacote TCP muito acima do tamanho normal. */
    private void injetarPacotesGigantes() {
        relogioMs += 10;
        pacotes.add(new PacoteIcmp(relogioMs, "203.0.113.150", servidores.get(0).getIp(), 65000,
                PacoteIcmp.TIPO_ECHO_REQUEST));
        relogioMs += 10;
        String alvo = servidores.get(servidores.size() > 1 ? 1 : 0).getIp();
        pacotes.add(new PacoteTcp(relogioMs, "192.168.1.51", alvo, 9000, portaAleatoria(), 443, false));
    }

    // -------------------------- tráfego normal --------------------------

    private void gerarPacoteNormal() {
        relogioMs += 1 + aleatorio.nextInt(8);
        String cliente = "192.168.1." + (10 + aleatorio.nextInt(50));
        String servidor = servidores.get(aleatorio.nextInt(servidores.size())).getIp();

        if (aleatorio.nextInt(100) < 90) {
            // Cliente acessando o servidor (web): de vez em quando abre uma conexão nova (SYN).
            boolean novaConexao = aleatorio.nextInt(100) < 8;
            int tamanho = novaConexao ? 60 : 40 + aleatorio.nextInt(1421);
            int porta = aleatorio.nextBoolean() ? 443 : 80;
            pacotes.add(new PacoteTcp(relogioMs, cliente, servidor, tamanho, portaAleatoria(), porta, novaConexao));
        } else {
            // Ping ocasional de um cliente para o servidor.
            pacotes.add(new PacoteIcmp(relogioMs, cliente, servidor, 64, PacoteIcmp.TIPO_ECHO_REQUEST));
        }
    }

    /** Porta alta, do tipo que o sistema operacional sorteia para quem inicia a comunicação. */
    private int portaAleatoria() {
        return 49152 + aleatorio.nextInt(16000);
    }
}
