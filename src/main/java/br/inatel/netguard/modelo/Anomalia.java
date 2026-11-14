package br.inatel.netguard.modelo;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

// Um alerta gerado por um detector. Implementa Comparable para poder ordenar
// a lista com Collections.sort (mais grave primeiro).
public class Anomalia implements Comparable<Anomalia> {

    private static final DateTimeFormatter FORMATO_HORARIO =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    // static: um contador só, compartilhado por todas as anomalias
    private static int proximoNumero = 1;

    private final int numero;
    private final String tipo;
    private final Severidade severidade;
    private final String ipSuspeito;
    private final String ipAlvo;
    private final long instanteMs;
    private final String descricao;

    // anomalia nova: o número vem do contador
    public Anomalia(String tipo, Severidade severidade, String ipSuspeito, String ipAlvo, long instanteMs,
                    String descricao) {
        this(proximoNumero++, tipo, severidade, ipSuspeito, ipAlvo, instanteMs, descricao);
    }

    // anomalia lida do banco: mantém o número que ela já tinha
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

    // chamado ao abrir o programa, para não repetir números que já estão no banco
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

    public String getIpAlvo() {
        return ipAlvo;
    }

    public long getInstanteMs() {
        return instanteMs;
    }

    public String getDescricao() {
        return descricao;
    }

    // mais grave primeiro; se empatar, a que aconteceu antes
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
