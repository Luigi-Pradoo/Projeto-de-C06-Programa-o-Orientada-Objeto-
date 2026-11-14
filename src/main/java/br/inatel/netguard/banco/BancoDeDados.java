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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

// Todo o acesso ao banco SQLite fica aqui (JDBC).
// Tabelas: empresas, servidores e alertas (os dois últimos apontam para a empresa).
// Implementa Notificador: para o motor, o banco é só mais um destino dos alertas.
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
        "CREATE TABLE IF NOT EXISTS alertas ("
            + " id          INTEGER PRIMARY KEY AUTOINCREMENT,"
            + " empresa_id  INTEGER NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,"
            + " numero      INTEGER NOT NULL,"
            + " instante_ms INTEGER NOT NULL,"
            + " tipo        TEXT NOT NULL,"
            + " severidade  TEXT NOT NULL,"
            + " ip_suspeito TEXT NOT NULL,"
            + " ip_alvo     TEXT NOT NULL,"
            + " descricao   TEXT NOT NULL)"
    };

    private final Connection conexao;
    private int empresaAnalisada = -1; // empresa da análise em andamento

    public BancoDeDados(Path arquivo) throws BancoDeDadosException {
        try {
            Class.forName("org.sqlite.JDBC"); // confere se o .jar do SQLite está no classpath
            if (arquivo.getParent() != null) {
                Files.createDirectories(arquivo.getParent());
            }
            conexao = DriverManager.getConnection("jdbc:sqlite:" + arquivo);
            Statement comando = conexao.createStatement();
            try {
                comando.execute("PRAGMA foreign_keys = ON"); // sem isso o SQLite ignora o CASCADE
                for (String sql : CRIAR_TABELAS) {
                    comando.execute(sql);
                }
            } finally {
                comando.close();
            }
        } catch (ClassNotFoundException e) {
            throw new BancoDeDadosException("Driver do SQLite não encontrado: rode o programa com "
                    + "lib/sqlite-jdbc-3.47.1.0.jar no classpath (veja o README)", e);
        } catch (IOException | SQLException e) {
            throw new BancoDeDadosException("Não foi possível abrir o banco " + arquivo, e);
        }
    }

    // ---------- cadastro ----------

    public int cadastrarEmpresa(Empresa empresa) throws BancoDeDadosException {
        String sql = "INSERT INTO empresas (nome, cnpj, responsavel, email) VALUES (?, ?, ?, ?)";
        try {
            // PreparedStatement: os valores vão nos "?", o que evita SQL Injection
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

    // lê as tabelas e monta os objetos Empresa, cada um com seus servidores
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

    // o CASCADE apaga junto os servidores e os alertas da empresa
    public boolean excluirEmpresa(int id) throws BancoDeDadosException {
        return excluir("DELETE FROM empresas WHERE id = ?", id);
    }

    public boolean excluirServidor(int id) throws BancoDeDadosException {
        return excluir("DELETE FROM servidores WHERE id = ?", id);
    }

    private boolean excluir(String sql, int id) throws BancoDeDadosException {
        try {
            PreparedStatement comando = conexao.prepareStatement(sql);
            try {
                comando.setInt(1, id);
                return comando.executeUpdate() > 0; // false se o id não existia
            } finally {
                comando.close();
            }
        } catch (SQLException e) {
            throw new BancoDeDadosException("não foi possível excluir o registro " + id, e);
        }
    }

    // ---------- alertas ----------

    // avisa de qual empresa são os próximos alertas
    public void iniciarAnalise(Empresa empresa) {
        empresaAnalisada = empresa.getId();
    }

    // método da interface Notificador: o motor chama igual ao da tela
    @Override
    public void notificar(Anomalia anomalia) throws BancoDeDadosException {
        if (empresaAnalisada < 0) {
            throw new BancoDeDadosException("alerta recebido antes de iniciarAnalise", null);
        }
        String sql = "INSERT INTO alertas (empresa_id, numero, instante_ms, tipo, severidade,"
                + " ip_suspeito, ip_alvo, descricao) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        try {
            PreparedStatement comando = conexao.prepareStatement(sql);
            try {
                comando.setInt(1, empresaAnalisada);
                comando.setInt(2, anomalia.getNumero());
                comando.setLong(3, anomalia.getInstanteMs());
                comando.setString(4, anomalia.getTipo());
                comando.setString(5, anomalia.getSeveridade().name());
                comando.setString(6, anomalia.getIpSuspeito());
                comando.setString(7, anomalia.getIpAlvo());
                comando.setString(8, anomalia.getDescricao());
                comando.executeUpdate();
            } finally {
                comando.close();
            }
        } catch (SQLException e) {
            throw new BancoDeDadosException("não foi possível gravar o alerta #" + anomalia.getNumero(), e);
        }
    }

    // lê os alertas salvos da empresa e transforma de volta em objetos Anomalia
    public List<Anomalia> listarAlertas(int empresaId) throws BancoDeDadosException {
        List<Anomalia> alertas = new ArrayList<>();
        try {
            PreparedStatement comando = conexao.prepareStatement(
                    "SELECT * FROM alertas WHERE empresa_id = ? ORDER BY id");
            try {
                comando.setInt(1, empresaId);
                ResultSet linhas = comando.executeQuery();
                while (linhas.next()) {
                    alertas.add(new Anomalia(linhas.getInt("numero"), linhas.getString("tipo"),
                            Severidade.valueOf(linhas.getString("severidade")), linhas.getString("ip_suspeito"),
                            linhas.getString("ip_alvo"), linhas.getLong("instante_ms"), linhas.getString("descricao")));
                }
            } finally {
                comando.close(); // fecha junto o ResultSet
            }
        } catch (SQLException e) {
            throw new BancoDeDadosException("não foi possível consultar os alertas", e);
        }
        return alertas;
    }

    // maior número de alerta já salvo (0 se não tem nenhum)
    public int maiorNumeroDeAlerta() throws BancoDeDadosException {
        try {
            Statement comando = conexao.createStatement();
            try {
                ResultSet linhas = comando.executeQuery("SELECT COALESCE(MAX(numero), 0) FROM alertas");
                linhas.next();
                return linhas.getInt(1);
            } finally {
                comando.close();
            }
        } catch (SQLException e) {
            throw new BancoDeDadosException("não foi possível consultar a numeração dos alertas", e);
        }
    }

    // id que o banco acabou de gerar no INSERT
    private int idGerado(PreparedStatement comando) throws SQLException {
        ResultSet chaves = comando.getGeneratedKeys();
        chaves.next();
        return chaves.getInt(1);
    }

    public void fechar() {
        try {
            conexao.close();
        } catch (SQLException e) {
            System.out.println("[AVISO] erro ao fechar o banco: " + e.getMessage());
        }
    }
}
