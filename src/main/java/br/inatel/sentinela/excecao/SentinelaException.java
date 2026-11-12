package br.inatel.sentinela.excecao;

/**
 * Exceção base de todos os erros "esperados" do Sentinela.
 *
 * Herda de Exception, então é uma exceção CHECADA: o compilador obriga quem
 * chama o método a tratar (try/catch) ou a declarar (throws). As exceções
 * específicas do sistema herdam desta, o que permite capturar qualquer uma
 * delas com um único catch (SentinelaException e).
 */
public class SentinelaException extends Exception {

    public SentinelaException(String mensagem) {
        super(mensagem);
    }

    public SentinelaException(String mensagem, Throwable causa) {
        super(mensagem, causa);
    }
}
