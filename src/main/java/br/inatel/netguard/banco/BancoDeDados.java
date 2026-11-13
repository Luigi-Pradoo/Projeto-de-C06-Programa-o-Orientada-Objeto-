package br.inatel.netguard.banco;

import br.inatel.netguard.analise.Notificador;
import br.inatel.netguard.excecao.BancoDeDadosException;
import br.inatel.netguard.excecao.CadastroInvalidoException;
import br.inatel.netguard.modelo.Anomalia;
import br.inatel.netguard.modelo.Empresa;
import br.inatel.netguard.modelo.Servidor;
import br.inatel.netguard.modelo.Severidade;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Toda a comunicação com o banco de dados SQLite, feita com JDBC.
 * Nenhuma outra classe do projeto escreve SQL.
 *
 * O banco tem quatro tabelas, ligadas por chaves estrangeiras:
 *   empresas  1 --- N  servidores
 *   empresas  1 --- N  analises  1 --- N  anomalias
 *
 * Implementa a interface Notificador: para o motor de detecção, o banco é só
 * mais um destino de alertas, igual à tela. Cada anomalia notificada vira uma
 * linha no banco.
 *
 * Recursos do banco (conexão e comandos) precisam ser fechados depois de
 * usados. Isso é feito no bloco finally, que sempre executa, com erro ou sem
 * erro (Aula 13). Fechar um comando (Statement) fecha junto o resultado
 * (ResultSet) que ele gerou.
 */
public class BancoDeDados implements Notificador {

    private static final String[] CRIAR_TABELAS = {
        "CREATE TABLE IF NOT EXISTS empresas ("
            + " id          INTEGER PRIMARY KEY AUTOINCREMENT,"
            + " nome        TEXT NOT NULL,"
            + " cnpj        TEXT NOT NULL UNIQUE,"
            + " responsavel TEXT NOT NULL,"
            + " email       TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS servidores ("
            + " id          INTEGER PRIMARY KEY AUTOINCREMENT,"
            + " empresa_id  INTEGER NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,"
            + " nome        TEXT NOT NULL,"
            + " ip          TEXT NOT NULL,"
            + " UNIQUE (empresa_id, ip))",
        "CREATE TABLE IF NOT EXISTS analises ("
            + " id          INTEGER PRIMARY KEY AUTOINCREMENT,"
            + " empresa_id  INTEGER NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,"
            + " data_hora   TEXT NOT NULL,"
            + " pacotes     INTEGER NOT NULL DEFAULT 0,"
            + " anomalias   INTEGER NOT NULL DEFAULT 0)",
        "CREATE TABLE IF NOT EXISTS anomalias ("
            + " id          INTEGER PRIMARY KEY AUTOINCREMENT,"
            + " analise_id  INTEGER NOT NULL REFERENCES analises(id) ON DELETE CASCADE,"
            + " servidor_id INTEGER REFERENCES servidores(id) ON DELETE SET NULL,"
            + " numero      INTEGER NOT NULL,"
            + " instante_ms INTEGER NOT NULL,"
            + " tipo        TEXT NOT NULL,"
            + " severidade  TEXT NOT NULL,"
            + " ip_suspeito TEXT NOT NULL,"
            + " ip_alvo     TEXT NOT NULL,"
            + " descricao   TEXT NOT NULL)"
    };

    private static final DateTimeFormatter FORMATO_DATA = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");

    private final Connection conexao;

    /** Análise em andamento: o id dela no banco e os servidores vigiados (IP -> id). */
    private int analiseAtual = -1;
    private final Map<String, Integer> servidoresVigiados = new HashMap<>();

    /**
     * Abre (ou cria) o arquivo do banco e garante que as tabelas existem.
     *
     * @throws BancoDeDadosException se o driver não estiver disponível ou o banco não abrir
     */
    public BancoDeDados(Path arquivo) throws BancoDeDadosException {
        try {
            // Confere se a biblioteca do SQLite (o .jar da pasta lib) está no classpath.
            Class.forName("org.sqlite.JDBC");
            if (arquivo.getParent() != null) {
                Files.createDirectories(arquivo.getParent());
            }
            conexao = DriverManager.getConnection("jdbc:sqlite:" + arquivo);
            Statement comando = conexao.createStatement();
            try {
                // O SQLite só respeita as chaves estrangeiras (e o CASCADE) com esta opção ligada.
                comando.execute("PRAGMA foreign_keys = ON");
                for (String sql : CRIAR_TABELAS) {
                    comando.execute(sql);
                }
            } finally {
                comando.close(); // o finally sempre executa: o comando é fechado mesmo se der erro
            }
        } catch (ClassNotFoundException e) {
            throw new BancoDeDadosException("Driver do SQLite não encontrado: rode o programa com "
                    + "lib/sqlite-jdbc-3.47.1.0.jar no classpath (veja o README)", e);
        } catch (IOException | SQLException e) {
            throw new BancoDeDadosException("Não foi possível abrir o banco " + arquivo, e);
        }
    }

    // ============================ CADASTRO ============================

    /** Grava uma empresa nova e devolve o id que o banco deu a ela. */
    public int cadastrarEmpresa(Empresa empresa) throws BancoDeDadosException {
        String sql = "INSERT INTO empresas (nome, cnpj, responsavel, email) VALUES (?, ?, ?, ?)";
        // PreparedStatement com "?": os valores vão separados do SQL, então um texto
        // com aspas não quebra o comando e não há risco de SQL Injection.
        try {
            PreparedStatement comando = conexao.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            try {
                comando.setString(1, empresa.getNome());
                comando.setString(2, empresa.getCnpj());
                comando.setString(3, empresa.getResponsavel());
                comando.setString(4, empresa.getEmail());
                comando.executeUpdate();
                return idGerado(comando);
            } finally {
                comando.close();
            }
        } catch (SQLException e) {
            if (e.getMessage().contains("UNIQUE")) {
                throw new BancoDeDadosException("já existe uma empresa com o CNPJ " + empresa.getCnpjFormatado(), e);
            }
            throw new BancoDeDadosException("não foi possível cadastrar a empresa", e);
        }
    }

    /** Grava um servidor novo e devolve o id que o banco deu a ele. */
    public int cadastrarServidor(Servidor servidor) throws BancoDeDadosException {
        String sql = "INSERT INTO servidores (empresa_id, nome, ip) VALUES (?, ?, ?)";
        try {
            PreparedStatement comando = conexao.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            try {
                comando.setInt(1, servidor.getEmpresaId());
                comando.setString(2, servidor.getNome());
                comando.setString(3, servidor.getIp());
                comando.executeUpdate();
                return idGerado(comando);
            } finally {
                comando.close();
            }
        } catch (SQLException e) {
            if (e.getMessage().contains("UNIQUE")) {
                throw new BancoDeDadosException("essa empresa já tem um servidor com o IP " + servidor.getIp(), e);
            }
            if (e.getMessage().contains("FOREIGN KEY")) {
                throw new BancoDeDadosException("não existe empresa com o id " + servidor.getEmpresaId(), e);
            }
            throw new BancoDeDadosException("não foi possível cadastrar o servidor", e);
        }
    }

    /**
     * Lê todas as empresas e os servidores de cada uma, e monta os objetos.
     * É aqui que as linhas das tabelas viram objetos Empresa e Servidor.
     */
    public List<Empresa> listarEmpresas() throws BancoDeDadosException {
        Map<Integer, Empresa> porId = new LinkedHashMap<>();
        try {
            Statement comando = conexao.createStatement();
            try {
                ResultSet linhas = comando.executeQuery("SELECT * FROM empresas ORDER BY nome");
                while (linhas.next()) {
                    Empresa empresa = new Empresa(linhas.getInt("id"), linhas.getString("nome"),
                            linhas.getString("cnpj"), linhas.getString("responsavel"), linhas.getString("email"));
                    porId.put(empresa.getId(), empresa);
                }
                linhas = comando.executeQuery("SELECT * FROM servidores ORDER BY id");
                while (linhas.next()) {
                    Servidor servidor = new Servidor(linhas.getInt("id"), linhas.getInt("empresa_id"),
                            linhas.getString("nome"), linhas.getString("ip"));
                    porId.get(servidor.getEmpresaId()).adicionarServidor(servidor);
                }
            } finally {
                comando.close();
            }
        } catch (SQLException e) {
            throw new BancoDeDadosException("não foi possível consultar as empresas", e);
        } catch (CadastroInvalidoException e) {
            throw new BancoDeDadosException("há um dado inválido gravado no banco: " + e.getMessage(), e);
        }
        return new ArrayList<>(porId.values());
    }

    /**
     * Exclui a empresa. Por causa do ON DELETE CASCADE, o banco apaga junto os
     * servidores e as análises dela.
     *
     * @return true se a empresa existia
     */
    public boolean excluirEmpresa(int id) throws BancoDeDadosException {
        return excluir("DELETE FROM empresas WHERE id = ?", id);
    }

    /** @return true se o servidor existia */
    public boolean excluirServidor(int id) throws BancoDeDadosException {
        return excluir("DELETE FROM servidores WHERE id = ?", id);
    }

    private boolean excluir(String sql, int id) throws BancoDeDadosException {
        try {
            PreparedStatement comando = conexao.prepareStatement(sql);
            try {
                comando.setInt(1, id);
                return comando.executeUpdate() > 0;
            } finally {
                comando.close();
            }
        } catch (SQLException e) {
            throw new BancoDeDadosException("não foi possível excluir o registro " + id, e);
        }
    }

    // ============================ HISTÓRICO ============================

    /** Registra o início de uma análise da empresa e guarda quais servidores ela tem. */
    public void iniciarAnalise(Empresa empresa) throws BancoDeDadosException {
        String sql = "INSERT INTO analises (empresa_id, data_hora) VALUES (?, ?)";
        try {
            PreparedStatement comando = conexao.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            try {
                comando.setInt(1, empresa.getId());
                comando.setString(2, LocalDateTime.now().format(FORMATO_DATA));
                comando.executeUpdate();
                analiseAtual = idGerado(comando);
            } finally {
                comando.close();
            }
        } catch (SQLException e) {
            throw new BancoDeDadosException("não foi possível registrar a análise", e);
        }
        servidoresVigiados.clear();
        for (Servidor servidor : empresa.getServidores()) {
            servidoresVigiados.put(servidor.getIp(), servidor.getId());
        }
    }

    /**
     * Grava a anomalia no banco. É o método da interface Notificador: o motor
     * chama este método do mesmo jeito que chama o da tela.
     */
    @Override
    public void notificar(Anomalia anomalia) throws BancoDeDadosException {
        if (analiseAtual < 0) {
            throw new BancoDeDadosException("anomalia recebida sem análise em andamento: chame iniciarAnalise antes",
                    null);
        }
        String sql = "INSERT INTO anomalias (analise_id, servidor_id, numero, instante_ms, tipo, severidade,"
                + " ip_suspeito, ip_alvo, descricao) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try {
            PreparedStatement comando = conexao.prepareStatement(sql);
            try {
                comando.setInt(1, analiseAtual);
                // Liga a anomalia ao servidor atacado, procurando o IP alvo entre os servidores vigiados.
                comando.setObject(2, servidoresVigiados.get(anomalia.getIpAlvo()));
                comando.setInt(3, anomalia.getNumero());
                comando.setLong(4, anomalia.getInstanteMs());
                comando.setString(5, anomalia.getTipo());
                comando.setString(6, anomalia.getSeveridade().name());
                comando.setString(7, anomalia.getIpSuspeito());
                comando.setString(8, anomalia.getIpAlvo());
                comando.setString(9, anomalia.getDescricao());
                comando.executeUpdate();
            } finally {
                comando.close();
            }
        } catch (SQLException e) {
            throw new BancoDeDadosException("não foi possível gravar a anomalia #" + anomalia.getNumero(), e);
        }
    }

    /** Completa a linha da análise com os totais, depois que ela termina. */
    public void finalizarAnalise(int pacotes, int anomalias) throws BancoDeDadosException {
        String sql = "UPDATE analises SET pacotes = ?, anomalias = ? WHERE id = ?";
        try {
            PreparedStatement comando = conexao.prepareStatement(sql);
            try {
                comando.setInt(1, pacotes);
                comando.setInt(2, anomalias);
                comando.setInt(3, analiseAtual);
                comando.executeUpdate();
            } finally {
                comando.close();
            }
        } catch (SQLException e) {
            throw new BancoDeDadosException("não foi possível finalizar a análise", e);
        }
    }

    /** @return as últimas análises, da mais recente para a mais antiga, já formatadas */
    public List<String> listarAnalises(int limite) throws BancoDeDadosException {
        String sql = "SELECT a.id, a.data_hora, e.nome, a.pacotes, a.anomalias"
                + " FROM analises a JOIN empresas e ON a.empresa_id = e.id"
                + " ORDER BY a.id DESC LIMIT ?";
        List<String> resultado = new ArrayList<>();
        try {
            PreparedStatement comando = conexao.prepareStatement(sql);
            try {
                comando.setInt(1, limite);
                ResultSet linhas = comando.executeQuery();
                while (linhas.next()) {
                    resultado.add(String.format("Análise %d | %s | %s | %d pacotes | %d anomalias",
                            linhas.getInt(1), linhas.getString(2), linhas.getString(3),
                            linhas.getInt(4), linhas.getInt(5)));
                }
            } finally {
                comando.close();
            }
        } catch (SQLException e) {
            throw new BancoDeDadosException("não foi possível consultar as análises", e);
        }
        return resultado;
    }

    /** Lê as anomalias da análise mais recente e as transforma de volta em objetos Anomalia. */
    public List<Anomalia> listarAnomaliasDaUltimaAnalise() throws BancoDeDadosException {
        return listarAnomalias("SELECT * FROM anomalias"
                + " WHERE analise_id = (SELECT MAX(id) FROM analises) ORDER BY numero", null);
    }

    // ===================== RELATÓRIO DE ANOMALIAS DA REDE =====================
    // Todas as consultas abaixo filtram por empresa: só entram as anomalias das
    // análises daquela empresa (JOIN com a tabela analises, WHERE empresa_id = ?).

    /** @return o maior número de anomalia já gravado (0 se ainda não há nenhuma) */
    public int maiorNumeroDeAnomalia() throws BancoDeDadosException {
        try {
            Statement comando = conexao.createStatement();
            try {
                ResultSet linhas = comando.executeQuery("SELECT COALESCE(MAX(numero), 0) FROM anomalias");
                linhas.next();
                return linhas.getInt(1);
            } finally {
                comando.close();
            }
        } catch (SQLException e) {
            throw new BancoDeDadosException("não foi possível consultar a numeração das anomalias", e);
        }
    }

    /** @return quantas análises a empresa já teve */
    public int contarAnalises(int empresaId) throws BancoDeDadosException {
        String sql = "SELECT COUNT(*) FROM analises WHERE empresa_id = ?";
        try {
            PreparedStatement comando = conexao.prepareStatement(sql);
            try {
                comando.setInt(1, empresaId);
                ResultSet linhas = comando.executeQuery();
                linhas.next();
                return linhas.getInt(1);
            } finally {
                comando.close();
            }
        } catch (SQLException e) {
            throw new BancoDeDadosException("não foi possível contar as análises", e);
        }
    }

    /** @return anomalias da empresa agrupadas por tipo de ataque (com a severidade), da mais frequente à menos */
    public Map<String, Integer> contarPorTipo(int empresaId) throws BancoDeDadosException {
        return contar("SELECT an.tipo || ' [' || an.severidade || ']', COUNT(*) AS total"
                + " FROM anomalias an JOIN analises a ON an.analise_id = a.id"
                + " WHERE a.empresa_id = ? GROUP BY an.tipo, an.severidade ORDER BY total DESC", empresaId);
    }

    /** @return anomalias da empresa agrupadas pelo IP de onde o ataque veio */
    public Map<String, Integer> contarPorIpAtacante(int empresaId) throws BancoDeDadosException {
        return contar("SELECT an.ip_suspeito, COUNT(*) AS total"
                + " FROM anomalias an JOIN analises a ON an.analise_id = a.id"
                + " WHERE a.empresa_id = ? GROUP BY an.ip_suspeito ORDER BY total DESC", empresaId);
    }

    /** @return anomalias da empresa agrupadas pelo servidor atacado (o mais atacado primeiro) */
    public Map<String, Integer> contarPorServidor(int empresaId) throws BancoDeDadosException {
        // JOIN junta três tabelas: a anomalia, a análise (para filtrar a empresa) e o servidor (para o nome).
        return contar("SELECT s.nome || ' (' || s.ip || ')', COUNT(*) AS total"
                + " FROM anomalias an JOIN analises a ON an.analise_id = a.id"
                + " JOIN servidores s ON an.servidor_id = s.id"
                + " WHERE a.empresa_id = ? GROUP BY s.id ORDER BY total DESC", empresaId);
    }

    /** @return todas as anomalias já registradas nas análises da empresa, como objetos Anomalia */
    public List<Anomalia> listarAnomaliasDaEmpresa(int empresaId) throws BancoDeDadosException {
        return listarAnomalias("SELECT an.* FROM anomalias an JOIN analises a ON an.analise_id = a.id"
                + " WHERE a.empresa_id = ? ORDER BY an.id", empresaId);
    }

    // ============================ AUXILIARES ============================

    /**
     * Executa uma consulta de agrupamento (rótulo, total) com um parâmetro "?" e
     * devolve o resultado como mapa. Usado pelos três métodos contarPor...
     */
    private Map<String, Integer> contar(String sql, int empresaId) throws BancoDeDadosException {
        Map<String, Integer> contagem = new LinkedHashMap<>(); // LinkedHashMap mantém a ordem do ORDER BY
        try {
            PreparedStatement comando = conexao.prepareStatement(sql);
            try {
                comando.setInt(1, empresaId);
                ResultSet linhas = comando.executeQuery();
                while (linhas.next()) {
                    contagem.put(linhas.getString(1), linhas.getInt(2));
                }
            } finally {
                comando.close();
            }
        } catch (SQLException e) {
            throw new BancoDeDadosException("não foi possível montar o relatório de anomalias", e);
        }
        return contagem;
    }

    /**
     * Executa uma consulta na tabela anomalias e transforma cada linha de volta em um objeto Anomalia.
     *
     * @param empresaId valor do "?" da consulta, ou null se a consulta não tiver "?"
     */
    private List<Anomalia> listarAnomalias(String sql, Integer empresaId) throws BancoDeDadosException {
        List<Anomalia> anomalias = new ArrayList<>();
        try {
            PreparedStatement comando = conexao.prepareStatement(sql);
            try {
                if (empresaId != null) {
                    comando.setInt(1, empresaId);
                }
                ResultSet linhas = comando.executeQuery();
                while (linhas.next()) {
                    anomalias.add(new Anomalia(linhas.getInt("numero"), linhas.getString("tipo"),
                            Severidade.valueOf(linhas.getString("severidade")), linhas.getString("ip_suspeito"),
                            linhas.getString("ip_alvo"), linhas.getLong("instante_ms"), linhas.getString("descricao")));
                }
            } finally {
                comando.close();
            }
        } catch (SQLException e) {
            throw new BancoDeDadosException("não foi possível consultar as anomalias", e);
        }
        return anomalias;
    }

    /**
     * Lê o id que o banco acabou de gerar no último INSERT. O ResultSet é
     * fechado junto com o comando, no finally de quem chamou este método.
     */
    private int idGerado(PreparedStatement comando) throws SQLException {
        ResultSet chaves = comando.getGeneratedKeys();
        chaves.next();
        return chaves.getInt(1);
    }

    /**
     * Fecha a conexão com o banco. É chamado no finally do main, então roda
     * sempre que o programa termina, com erro ou sem erro.
     */
    public void fechar() {
        try {
            conexao.close();
        } catch (SQLException e) {
            System.out.println("[AVISO] erro ao fechar o banco: " + e.getMessage());
        }
    }
}
