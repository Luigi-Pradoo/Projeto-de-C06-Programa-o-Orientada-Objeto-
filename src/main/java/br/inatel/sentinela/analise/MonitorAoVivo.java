package br.inatel.sentinela.analise;

import br.inatel.sentinela.modelo.PacoteRede;

/**
 * Mostra o tráfego na tela enquanto a análise acontece.
 *
 * Mostrar os 20.000 pacotes inundaria o terminal, então o monitor mostra uma
 * AMOSTRA (1 pacote a cada "intervalo") e SEMPRE os pacotes que geraram alerta.
 * De tempos em tempos imprime também uma linha de progresso.
 *
 * Quem decide o que é mostrado é esta classe; o motor só avisa que um pacote
 * foi analisado. Assim o MotorDeteccao continua sem nenhum System.out de
 * tráfego, e o modo ao vivo pode ser ligado ou desligado sem mexer nele.
 */
public class MonitorAoVivo {

    private final int intervalo;
    private int totalDePacotes;
    private int alertasAteAgora;

    /**
     * @param intervalo mostra 1 pacote a cada "intervalo" pacotes
     * @throws IllegalArgumentException se o intervalo for menor que 1
     */
    public MonitorAoVivo(int intervalo) {
        if (intervalo < 1) {
            throw new IllegalArgumentException("o intervalo do monitor deve ser pelo menos 1");
        }
        this.intervalo = intervalo;
    }

    /** Chamado pelo motor antes do primeiro pacote. */
    public void iniciar(int totalDePacotes) {
        this.totalDePacotes = totalDePacotes;
        this.alertasAteAgora = 0;
        System.out.println();
        System.out.println("---------------- TRÁFEGO AO VIVO ----------------");
        System.out.println("(amostra de 1 a cada " + intervalo + " pacotes; pacotes que geraram alerta aparecem sempre)");
        System.out.println();
    }

    /**
     * Chamado pelo motor depois que todos os detectores olharam o pacote.
     *
     * @param numero          posição do pacote na sequência (começa em 1)
     * @param pacote          o pacote analisado
     * @param alertasDoPacote quantas anomalias este pacote gerou
     */
    public void pacoteAnalisado(int numero, PacoteRede pacote, int alertasDoPacote) {
        alertasAteAgora += alertasDoPacote;
        boolean suspeito = alertasDoPacote > 0;

        if (suspeito || numero % intervalo == 0) {
            // POLIMORFISMO: descrever() é abstrato em PacoteRede. Um pacote TCP mostra
            // portas e a flag SYN; um ICMP mostra o tipo da mensagem.
            System.out.printf("  [%5d] %s%s%n", numero, pacote.descrever(), suspeito ? "   <<< SUSPEITO" : "");
        }

        // Linha de progresso a cada 25% do tráfego (só se iniciar() informou o total).
        int quarto = Math.max(1, totalDePacotes / 4);
        if (totalDePacotes > 0 && numero % quarto == 0) {
            System.out.printf("  ...... %d de %d pacotes analisados (%d%%), %d alerta(s) até agora ......%n",
                    numero, totalDePacotes, numero * 100 / totalDePacotes, alertasAteAgora);
        }
    }
}
