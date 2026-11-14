package br.inatel.netguard.excecao;

// Erro ao abrir, gravar, consultar ou excluir no banco. Guarda a SQLException original como causa.
public class BancoDeDadosException extends NetGuardException {

    public BancoDeDadosException(String mensagem, Throwable causa) {
        super(mensagem, causa);
    }
}
