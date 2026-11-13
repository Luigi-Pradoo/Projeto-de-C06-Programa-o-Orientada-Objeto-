package br.inatel.netguard.modelo;

/**
 * Nível de gravidade de uma anomalia.
 *
 * Um enum é uma classe com um conjunto FIXO de objetos: só existem estes
 * quatro. Cada um guarda um peso, usado para ordenar os alertas do mais
 * grave para o menos grave.
 */
public enum Severidade {

    BAIXA(1),
    MEDIA(2),
    ALTA(3),
    CRITICA(4);

    private final int peso;

    Severidade(int peso) {
        this.peso = peso;
    }

    public int getPeso() {
        return peso;
    }
}
