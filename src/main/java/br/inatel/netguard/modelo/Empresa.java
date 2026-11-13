package br.inatel.netguard.modelo;

import br.inatel.netguard.excecao.CadastroInvalidoException;

import java.util.ArrayList;
import java.util.List;

/**
 * Uma empresa cliente, cujos servidores o NetGuard vigia.
 *
 * Uma empresa TEM VÁRIOS servidores (associação de 1 para N). No objeto isso
 * é uma lista; no banco de dados é a coluna empresa_id da tabela servidores.
 */
public class Empresa {

    private final int id;
    private final String nome;
    private final String cnpj;
    private final String responsavel;
    private final String email;
    private final List<Servidor> servidores = new ArrayList<>();

    /**
     * Cria uma empresa NOVA, que ainda não está no banco (por isso ainda não tem id).
     *
     * @throws CadastroInvalidoException se algum dado for inválido
     */
    public Empresa(String nome, String cnpj, String responsavel, String email) throws CadastroInvalidoException {
        this(0, nome, cnpj, responsavel, email);
    }

    /**
     * Recria uma empresa lida do banco, com o id que o banco deu a ela.
     * É uma sobrecarga do construtor acima.
     *
     * @throws CadastroInvalidoException se algum dado for inválido
     */
    public Empresa(int id, String nome, String cnpj, String responsavel, String email)
            throws CadastroInvalidoException {
        if (nome == null || nome.isBlank()) {
            throw new CadastroInvalidoException("o nome da empresa não pode ficar vazio");
        }
        // Aceita o CNPJ com ou sem pontuação e guarda só os dígitos.
        String digitos = cnpj == null ? "" : cnpj.replaceAll("[^0-9]", "");
        if (digitos.length() != 14) {
            throw new CadastroInvalidoException("o CNPJ precisa ter 14 dígitos: " + cnpj);
        }
        if (responsavel == null || responsavel.isBlank()) {
            throw new CadastroInvalidoException("o nome do responsável não pode ficar vazio");
        }
        if (email == null || !email.contains("@")) {
            throw new CadastroInvalidoException("e-mail inválido: " + email);
        }
        this.id = id;
        this.nome = nome.trim();
        this.cnpj = digitos;
        this.responsavel = responsavel.trim();
        this.email = email.trim();
    }

    /** Liga um servidor a esta empresa (usado ao carregar os dados do banco). */
    public void adicionarServidor(Servidor servidor) {
        servidores.add(servidor);
    }

    /** @return uma CÓPIA da lista, para ninguém alterar os servidores da empresa por fora */
    public List<Servidor> getServidores() {
        return new ArrayList<>(servidores);
    }

    public int getId() {
        return id;
    }

    public String getNome() {
        return nome;
    }

    public String getCnpj() {
        return cnpj;
    }

    /** @return o CNPJ no formato 00.000.000/0000-00 */
    public String getCnpjFormatado() {
        return cnpj.substring(0, 2) + "." + cnpj.substring(2, 5) + "." + cnpj.substring(5, 8) + "/"
                + cnpj.substring(8, 12) + "-" + cnpj.substring(12);
    }

    public String getResponsavel() {
        return responsavel;
    }

    public String getEmail() {
        return email;
    }

    @Override
    public String toString() {
        return "[" + id + "] " + nome + " | CNPJ " + getCnpjFormatado() + " | responsável: " + responsavel
                + " <" + email + ">";
    }
}
