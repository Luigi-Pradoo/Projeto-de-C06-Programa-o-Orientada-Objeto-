package br.inatel.netguard.modelo;

// Nível de gravidade de um alerta. O peso é usado para ordenar (mais grave primeiro).
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
