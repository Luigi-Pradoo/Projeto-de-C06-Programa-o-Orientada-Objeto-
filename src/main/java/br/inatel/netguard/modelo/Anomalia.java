package br.inatel.netguard.modelo;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Registro de um comportamento suspeito encontrado por um detector.
 *
 * É um objeto imutável: depois de criado, nenhum atributo muda (todos são
 * final e não existem setters). Um alerta registrado não deve ser alterado.
 *
 * Implementa a interface Comparable do Java, o que permite ordenar uma lista
 * de anomalias da mais grave para a menos grave com Collections.sort.
 */
public class Anomalia implements Comparable<Anomalia> {

    private static final DateTimeFormatter FORMATO_HORARIO =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    /** Atributo de CLASSE (static): é um só, compartilhado por todas as anomalias. */
    private static int proximoNumero = 1;

    private final int numero;
    private final String tipo;
    private final Severidade severidade;
    private final String ipSuspeito;
    private final String ipAlvo;
    private final long instanteMs;
    private final String descricao;

    /** Cria uma anomalia NOVA, detectada agora. O número vem do contador da classe. */
    public Anomalia(String tipo, Severidade severidade, String ipSuspeito, String ipAlvo, long instanteMs,
                    String descricao) {
        this(proximoNumero++, tipo, severidade, ipSuspeito, ipAlvo, instanteMs, descricao);
    }

    /**
     * Recria uma anomalia que JÁ EXISTIA (lida do banco de dados), mantendo o
     * número que ela tinha. É uma sobrecarga do construtor acima.
     */
    public Anomalia(int numero, String tipo, Severidade severidade, String ipSuspeito, String ipAlvo,
                    long instanteMs, String descricao) {
        this.numero = numero;
        this.tipo = tipo;
        this.severidade = severidade;
        this.ipSuspeito = ipSuspeito;
        this.ipAlvo = ipAlvo;
        this.instanteMs = instanteMs;
        this.descricao = descricao;
    }

    /**
     * Método STATIC: age sobre a classe, não sobre um objeto. Faz a numeração
     * continuar depois da maior anomalia já gravada no banco, para o programa
     * não repetir o #1 cada vez que é aberto.
     */
    public static void continuarNumeracaoApos(int ultimoNumero) {
        proximoNumero = Math.max(proximoNumero, ultimoNumero + 1);
    }

    public int getNumero() {
        return numero;
    }

    public String getTipo() {
        return tipo;
    }

    public Severidade getSeveridade() {
        return severidade;
    }

    public String getIpSuspeito() {
        return ipSuspeito;
    }

    /** @return o IP do servidor que foi alvo da anomalia */
    public String getIpAlvo() {
        return ipAlvo;
    }

    public long getInstanteMs() {
        return instanteMs;
    }

    public String getDescricao() {
        return descricao;
    }

    /**
     * Ordem natural: primeiro as mais graves; em caso de empate, a que aconteceu antes.
     * Devolve negativo se esta vem antes da outra, positivo se vem depois.
     */
    @Override
    public int compareTo(Anomalia outra) {
        int porSeveridade = Integer.compare(outra.severidade.getPeso(), this.severidade.getPeso());
        if (porSeveridade != 0) {
            return porSeveridade;
        }
        return Long.compare(this.instanteMs, outra.instanteMs);
    }

    @Override
    public String toString() {
        return "#" + numero + " [" + severidade + "] " + FORMATO_HORARIO.format(Instant.ofEpochMilli(instanteMs))
                + " | " + tipo + " | de " + ipSuspeito + " | " + descricao;
    }
}
