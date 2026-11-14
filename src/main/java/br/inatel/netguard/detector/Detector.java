package br.inatel.netguard.detector;

import br.inatel.netguard.modelo.Anomalia;
import br.inatel.netguard.modelo.PacoteRede;
import br.inatel.netguard.modelo.Severidade;

import java.util.HashSet;
import java.util.Set;

// Classe mãe de todos os detectores. O analisar() tem os passos fixos e chama
// inspecionar(), que é abstrato: cada detector escreve só a sua regra.
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

    // final: as subclasses não podem mudar essa sequência
    // devolve null quando o pacote está normal
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

    // por padrão aceita qualquer pacote; quem quiser filtrar sobrescreve
    protected boolean aceita(PacoteRede pacote) {
        return true;
    }

    // a regra de cada detector
    protected abstract Anomalia inspecionar(PacoteRede pacote);

    protected Anomalia novaAnomalia(PacoteRede pacote, String descricao) {
        return new Anomalia(nome, severidade, pacote.getIpOrigem(), pacote.getIpDestino(),
                pacote.getInstanteMs(), descricao);
    }

    // evita alerta repetido: o add do Set devolve false se a chave já existia
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
