package br.inatel.netguard.excecao;

// Dado de cadastro inválido (nome vazio, CNPJ errado, IP errado...).
public class CadastroInvalidoException extends NetGuardException {

    public CadastroInvalidoException(String mensagem) {
        super(mensagem);
    }
}
