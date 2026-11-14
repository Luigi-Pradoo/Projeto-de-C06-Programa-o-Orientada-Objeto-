package br.inatel.netguard;

import br.inatel.netguard.analise.FonteDeTrafego;
import br.inatel.netguard.analise.LeitorPcap;
import br.inatel.netguard.analise.MotorDeteccao;
import br.inatel.netguard.analise.NotificadorConsole;
import br.inatel.netguard.analise.SimuladorTrafego;
import br.inatel.netguard.banco.BancoDeDados;
import br.inatel.netguard.detector.Detector;
import br.inatel.netguard.detector.DetectorPortScan;
import br.inatel.netguard.detector.DetectorPortaSuspeita;
import br.inatel.netguard.detector.DetectorSynFlood;
import br.inatel.netguard.detector.DetectorTamanhoAnormal;
import br.inatel.netguard.excecao.NetGuardException;
import br.inatel.netguard.modelo.Anomalia;
import br.inatel.netguard.modelo.Empresa;
import br.inatel.netguard.modelo.PacoteRede;
import br.inatel.netguard.modelo.Servidor;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;

// Menu do sistema. É a única classe que cria os detectores e notificadores concretos.
public class Principal {

    private static final int PACOTES_POR_ANALISE = 20000;

    private final BancoDeDados banco;
    private final Scanner teclado = new Scanner(System.in);

    public Principal(BancoDeDados banco) {
        this.banco = banco;
    }

    public static void main(String[] args) {
        BancoDeDados banco = null;
        try {
            banco = new BancoDeDados(Paths.get("dados", "netguard.db"));
            Principal aplicacao = new Principal(banco);
            aplicacao.cadastrarExemploSeVazio();
            Anomalia.continuarNumeracaoApos(banco.maiorNumeroDeAlerta());
            aplicacao.executarMenu();
        } catch (NetGuardException e) {
            System.out.println("[ERRO] " + e.getMessage());
        } finally {
            // roda sempre, com erro ou sem erro
            if (banco != null) {
                banco.fechar();
            }
        }
    }

    private void executarMenu() {
        boolean continuar = true;
        while (continuar) {
            System.out.println();
            System.out.println("=== NETGUARD - Detecção de Anomalias em Redes ===");
            System.out.println("1 - Cadastrar empresa");
            System.out.println("2 - Cadastrar servidor");
            System.out.println("3 - Listar empresas e servidores");
            System.out.println("4 - Excluir empresa");
            System.out.println("5 - Excluir servidor");
            System.out.println("6 - Analisar a rede de uma empresa");
            System.out.println("7 - Ver alertas salvos de uma empresa");
            System.out.println("0 - Sair");
            String opcao = lerTexto("Opção");
            try {
                switch (opcao) {
                    case "1": cadastrarEmpresa(); break;
                    case "2": cadastrarServidor(); break;
                    case "3": listarEmpresas(); break;
                    case "4": excluirEmpresa(); break;
                    case "5": excluirServidor(); break;
                    case "6": analisar(); break;
                    case "7": verAlertas(); break;
                    case "0": continuar = false; break;
                    default: System.out.println("Opção inválida.");
                }
            } catch (NetGuardException e) {
                // pega qualquer exceção nossa (cadastro inválido ou erro no banco)
                System.out.println("[ERRO] " + e.getMessage());
            } catch (IllegalArgumentException e) {
                System.out.println("[ERRO] " + e.getMessage());
            }
        }
        System.out.println("NetGuard encerrado.");
    }

    // ---------- cadastro ----------

    private void cadastrarEmpresa() throws NetGuardException {
        // o construtor de Empresa já valida os dados
        Empresa empresa = new Empresa(lerTexto("Nome da empresa"), lerTexto("CNPJ"),
                lerTexto("Nome do responsável"), lerTexto("E-mail do responsável"));
        int id = banco.cadastrarEmpresa(empresa);
        System.out.println("Empresa cadastrada com o id " + id + ".");
    }

    private void cadastrarServidor() throws NetGuardException {
        listarEmpresas();
        Servidor servidor = new Servidor(lerInteiro("Id da empresa dona do servidor"),
                lerTexto("Nome do servidor"), lerTexto("Endereço IP"));
        int id = banco.cadastrarServidor(servidor);
        System.out.println("Servidor cadastrado com o id " + id + ".");
    }

    private void listarEmpresas() throws NetGuardException {
        List<Empresa> empresas = banco.listarEmpresas();
        if (empresas.isEmpty()) {
            System.out.println("Nenhuma empresa cadastrada.");
        }
        for (Empresa empresa : empresas) {
            System.out.println(empresa);
            for (Servidor servidor : empresa.getServidores()) {
                System.out.println("      servidor " + servidor);
            }
        }
    }

    private void excluirEmpresa() throws NetGuardException {
        listarEmpresas();
        int id = lerInteiro("Id da empresa a excluir (os servidores e alertas dela também serão apagados)");
        System.out.println(banco.excluirEmpresa(id) ? "Empresa excluída." : "Não existe empresa com esse id.");
    }

    private void excluirServidor() throws NetGuardException {
        listarEmpresas();
        int id = lerInteiro("Id do servidor a excluir");
        System.out.println(banco.excluirServidor(id) ? "Servidor excluído." : "Não existe servidor com esse id.");
    }

    // na primeira vez cadastra uma empresa de exemplo para dar para testar direto
    private void cadastrarExemploSeVazio() throws NetGuardException {
        if (!banco.listarEmpresas().isEmpty()) {
            return;
        }
        int id = banco.cadastrarEmpresa(
                new Empresa("Empresa Exemplo", "12.345.678/0001-90", "Maria Souza", "maria@exemplo.com"));
        banco.cadastrarServidor(new Servidor(id, "Servidor Web", "10.0.0.10"));
        banco.cadastrarServidor(new Servidor(id, "Servidor de Arquivos", "10.0.0.20"));
        banco.cadastrarServidor(new Servidor(id, "Servidor de E-mail", "10.0.0.25"));
        System.out.println("Banco vazio: foi cadastrada a \"Empresa Exemplo\" com 3 servidores para teste.");
    }

    // ---------- análise ----------

    private List<Detector> criarDetectores() {
        List<Detector> detectores = new ArrayList<>();
        detectores.add(new DetectorSynFlood(1000, 100));    // mais de 100 SYN em 1 s
        detectores.add(new DetectorPortScan(3000, 20));     // mais de 20 portas em 3 s
        detectores.add(new DetectorPortaSuspeita());
        detectores.add(new DetectorTamanhoAnormal(1500));   // mais de 1500 bytes
        return detectores;
    }

    // devolve null se o id não existir
    private Empresa escolherEmpresa(String pergunta) throws NetGuardException {
        listarEmpresas();
        int id = lerInteiro(pergunta);
        for (Empresa empresa : banco.listarEmpresas()) {
            if (empresa.getId() == id) {
                return empresa;
            }
        }
        System.out.println("Não existe empresa com esse id.");
        return null;
    }

    private void analisar() throws NetGuardException {
        Empresa empresa = escolherEmpresa("Id da empresa a analisar");
        if (empresa == null) {
            return;
        }
        System.out.println("De onde vem o tráfego?");
        System.out.println("  1 - Simulado (ataques de exemplo)");
        System.out.println("  2 - Arquivo de captura .pcap (Wireshark)");
        String opcaoFonte = lerTexto("Fonte");

        // a variável é do tipo da interface, então serve para as duas fontes
        FonteDeTrafego fonte;
        if (opcaoFonte.equals("2")) {
            String caminho = lerTexto("Caminho do arquivo .pcap").replace("\"", ""); // tira as aspas do "Copiar como caminho"
            fonte = new LeitorPcap(Paths.get(caminho));
        } else {
            fonte = new SimuladorTrafego(empresa.getServidores(), PACOTES_POR_ANALISE);
        }
        List<PacoteRede> pacotes = fonte.obterPacotes();
        if (pacotes.isEmpty()) {
            System.out.println("Nenhum pacote IPv4 com TCP ou ICMP encontrado (" + fonte.descrever() + ").");
            return;
        }

        List<Detector> detectores = criarDetectores();
        MotorDeteccao motor = new MotorDeteccao(detectores);
        // para o motor, a tela e o banco são os dois só "Notificador"
        motor.adicionarNotificador(new NotificadorConsole());
        motor.adicionarNotificador(banco);

        System.out.println();
        System.out.println("Analisando " + pacotes.size() + " pacotes para a empresa " + empresa.getNome()
                + " (" + fonte.descrever() + ")...");
        banco.iniciarAnalise(empresa);
        motor.executar(pacotes);
        int total = motor.getAnomalias().size();

        System.out.println();
        System.out.println("---------------- RESUMO ----------------");
        System.out.println("Pacotes analisados: " + pacotes.size());
        if (motor.getFalhasDeNotificacao() == 0) {
            System.out.println("Anomalias         : " + total + " (salvas no banco de dados)");
        } else {
            System.out.println("Anomalias         : " + total + " (ATENÇÃO: " + motor.getFalhasDeNotificacao()
                    + " alerta(s) não foram gravados no banco; veja os [ERRO] acima)");
        }
        for (Detector detector : detectores) {
            System.out.println("  - " + detector.getNome() + ": inspecionou " + detector.getPacotesInspecionados()
                    + " pacotes, " + detector.getAnomaliasGeradas() + " anomalia(s)");
        }
    }

    private void verAlertas() throws NetGuardException {
        Empresa empresa = escolherEmpresa("Id da empresa");
        if (empresa == null) {
            return;
        }
        List<Anomalia> alertas = banco.listarAlertas(empresa.getId());
        System.out.println();
        System.out.println("------- ALERTAS SALVOS: " + empresa.getNome() + " (" + alertas.size() + ") -------");
        if (alertas.isEmpty()) {
            System.out.println("Nenhum alerta salvo para esta empresa. Use a opção 6.");
            return;
        }
        Collections.sort(alertas); // usa o compareTo da Anomalia: mais graves primeiro
        for (Anomalia alerta : alertas) {
            System.out.println(alerta);
        }
    }

    // ---------- teclado ----------

    private String lerTexto(String pergunta) {
        System.out.print(pergunta + ": ");
        return teclado.hasNextLine() ? teclado.nextLine().trim() : "0";
    }

    private int lerInteiro(String pergunta) {
        String texto = lerTexto(pergunta);
        try {
            return Integer.parseInt(texto);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("\"" + texto + "\" não é um número inteiro");
        }
    }
}
