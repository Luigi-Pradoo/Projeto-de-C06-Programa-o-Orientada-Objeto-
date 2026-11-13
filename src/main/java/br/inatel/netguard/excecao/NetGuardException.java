package br.inatel.netguard.excecao;

/**
 * Exceção base de todos os erros "esperados" do NetGuard.
 *
 * Herda de Exception, então é uma exceção CHECADA: o compilador obriga quem
 * chama o método a tratar (try/catch) ou a declarar (throws). As exceções
 * específicas do sistema herdam desta, o que permite capturar qualquer uma
 * delas com um único catch (NetGuardException e).
 */
public class NetGuardException extends Exception {

    public NetGuardException(String mensagem) {
        super(mensagem);
    }

    public NetGuardException(String mensagem, Throwable causa) {
        super(mensagem, causa);
    }
}
