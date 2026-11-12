package br.inatel.sentinela.excecao;

/**
 * Lançada quando o usuário digita um dado de cadastro inválido: nome vazio,
 * CNPJ sem 14 dígitos, e-mail sem @, endereço IP impossível...
 *
 * É um erro esperado (gente digita errado), por isso é checada: o menu é
 * obrigado a tratar, avisando o usuário em vez de deixar o programa cair.
 */
public class CadastroInvalidoException extends SentinelaException {

    public CadastroInvalidoException(String mensagem) {
        super(mensagem);
    }
}
