package br.inatel.netguard.excecao;

// Exceção base do sistema. Herda de Exception, então é checada.
public class NetGuardException extends Exception {

    public NetGuardException(String mensagem) {
        super(mensagem);
    }

    public NetGuardException(String mensagem, Throwable causa) {
        super(mensagem, causa);
    }
}
