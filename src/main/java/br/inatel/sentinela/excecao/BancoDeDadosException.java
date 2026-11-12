package br.inatel.sentinela.excecao;

/**
 * Lançada quando uma operação no banco de dados falha (não foi possível
 * abrir o banco, gravar, consultar ou excluir).
 *
 * Embrulha a SQLException do JDBC, que é genérica, em um erro com
 * significado para o sistema, guardando a original como causa.
 */
public class BancoDeDadosException extends SentinelaException {

    public BancoDeDadosException(String mensagem, Throwable causa) {
        super(mensagem, causa);
    }
}
