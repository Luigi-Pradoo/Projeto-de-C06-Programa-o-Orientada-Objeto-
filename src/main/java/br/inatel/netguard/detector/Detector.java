package br.inatel.netguard.detector;

import br.inatel.netguard.modelo.Anomalia;
import br.inatel.netguard.modelo.PacoteRede;
import br.inatel.netguard.modelo.Severidade;

import java.util.HashSet;
import java.util.Set;

/**
 * Classe abstrata que representa qualquer regra de detecção de anomalias.
 *
 * Guarda o que é igual em todos os detectores (nome, severidade, contadores)
 * e a "receita" de como um pacote é analisado. O método analisar() define os
 * passos fixos e chama inspecionar(), que é abstrato: cada detector concreto
 * só escreve a sua regra.
 */
public abstract class Detector {

    private final String nome;
    private final Severidade severidade;
    private final Set<String> jaAlertados = new HashSet<>();
    private int pacotesInspecionados;
    private int anomaliasGeradas;

    protected Detector(String nome, Severidade severidade) {
        this.nome = nome;
        this.severidade = severidade;
    }

    /**
     * Receita fixa da análise: filtra, conta, inspeciona e conta de novo.
     * É final para que nenhuma subclasse possa mudar essa sequência.
     *
     * @return a anomalia encontrada, ou null se o pacote está normal
     */
    public final Anomalia analisar(PacoteRede pacote) {
        if (!aceita(pacote)) {
            return null;
        }
        pacotesInspecionados++;
        Anomalia resultado = inspecionar(pacote);
        if (resultado != null) {
            anomaliasGeradas++;
        }
        return resultado;
    }

    /**
     * Diz se este detector se interessa pelo pacote. O padrão é aceitar todos;
     * as subclasses sobrescrevem para filtrar (ex.: só TCP).
     */
    protected boolean aceita(PacoteRede pacote) {
        return true;
    }

    /**
     * A regra de detecção propriamente dita. Cada subclasse implementa a sua.
     *
     * @return a anomalia encontrada, ou null se o pacote não tem nada de suspeito
     */
    protected abstract Anomalia inspecionar(PacoteRede pacote);

    /** Cria uma anomalia já com o nome e a severidade deste detector. */
    protected Anomalia novaAnomalia(PacoteRede pacote, String descricao) {
        return new Anomalia(nome, severidade, pacote.getIpOrigem(), pacote.getIpDestino(),
                pacote.getInstanteMs(), descricao);
    }

    /**
     * Evita repetir o mesmo alerta: devolve true só na primeira vez que a
     * chave aparece (Set.add devolve false quando o elemento já existia).
     */
    protected boolean primeiraVez(String chave) {
        return jaAlertados.add(chave);
    }

    public String getNome() {
        return nome;
    }

    public int getPacotesInspecionados() {
        return pacotesInspecionados;
    }

    public int getAnomaliasGeradas() {
        return anomaliasGeradas;
    }
}
