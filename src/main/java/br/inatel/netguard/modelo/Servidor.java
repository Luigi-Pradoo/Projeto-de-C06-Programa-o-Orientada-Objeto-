package br.inatel.netguard.modelo;

import br.inatel.netguard.excecao.CadastroInvalidoException;

/**
 * Um servidor de uma empresa, identificado pelo endereço IP.
 *
 * Na análise, o NetGuard vigia o tráfego que chega aos servidores
 * cadastrados da empresa escolhida.
 */
public class Servidor {

    private final int id;
    private final int empresaId;
    private final String nome;
    private final String ip;

    /**
     * Cria um servidor NOVO, que ainda não está no banco.
     *
     * @throws CadastroInvalidoException se o nome estiver vazio ou o IP for inválido
     */
    public Servidor(int empresaId, String nome, String ip) throws CadastroInvalidoException {
        this(0, empresaId, nome, ip);
    }

    /**
     * Recria um servidor lido do banco, com o id que o banco deu a ele.
     *
     * @throws CadastroInvalidoException se o nome estiver vazio ou o IP for inválido
     */
    public Servidor(int id, int empresaId, String nome, String ip) throws CadastroInvalidoException {
        if (nome == null || nome.isBlank()) {
            throw new CadastroInvalidoException("o nome do servidor não pode ficar vazio");
        }
        if (!PacoteRede.ehIpv4Valido(ip)) {
            throw new CadastroInvalidoException("endereço IP inválido: " + ip);
        }
        this.id = id;
        this.empresaId = empresaId;
        this.nome = nome.trim();
        this.ip = ip.trim();
    }

    public int getId() {
        return id;
    }

    public int getEmpresaId() {
        return empresaId;
    }

    public String getNome() {
        return nome;
    }

    public String getIp() {
        return ip;
    }

    @Override
    public String toString() {
        return "[" + id + "] " + nome + " (" + ip + ")";
    }
}
