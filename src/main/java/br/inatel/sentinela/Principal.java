package br.inatel.sentinela;

import br.inatel.sentinela.analise.FonteDeTrafego;
import br.inatel.sentinela.analise.LeitorPcap;
import br.inatel.sentinela.analise.MonitorAoVivo;
import br.inatel.sentinela.analise.MotorDeteccao;
import br.inatel.sentinela.analise.NotificadorConsole;
import br.inatel.sentinela.analise.SimuladorTrafego;
import br.inatel.sentinela.banco.BancoDeDados;
import br.inatel.sentinela.detector.Detector;
import br.inatel.sentinela.detector.DetectorPortScan;
import br.inatel.sentinela.detector.DetectorPortaSuspeita;
import br.inatel.sentinela.detector.DetectorSynFlood;
import br.inatel.sentinela.detector.DetectorTamanhoAnormal;
import br.inatel.sentinela.excecao.SentinelaException;
import br.inatel.sentinela.modelo.Anomalia;
import br.inatel.sentinela.modelo.Empresa;
import br.inatel.sentinela.modelo.PacoteRede;
import br.inatel.sentinela.modelo.Servidor;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

/**
 * Ponto de entrada do Sentinela: o menu de cadastro e de análise.
 *
 * É a única classe que conhece as classes CONCRETAS (quais detectores, quais
 * notificadores). Ela monta as peças e entrega para o motor, que só enxerga
 * os tipos gerais.
 */
public class Principal {

    private static final Path ARQUIVO_DO_BANCO = Paths.get("dados", "sentinela.db");
    private static final int PACOTES_POR_ANALISE = 20000;
    /** No modo ao vivo, mostra 1 pacote a cada 200 (cerca de 100 linhas de tráfego). */
    private static final int INTERVALO_AO_VIVO = 200;

    private final BancoDeDados banco;
    private final Scanner teclado = new Scanner(System.in);

    public Principal(BancoDeDados banco) {
        this.banco = banco;
    }

    public static void main(String[] args) {
        BancoDeDados banco = null;
        try {
            banco = new BancoDeDados(ARQUIVO_DO_BANCO);
            Principal aplicacao = new Principal(banco);
            aplicacao.cadastrarExemploSeVazio();
            Anomalia.continuarNumeracaoApos(banco.maiorNumeroDeAnomalia());
            aplicacao.executarMenu();
        } catch (SentinelaException e) {
            System.out.println("[ERRO] " + e.getMessage());
        } finally {
            // O finally sempre executa: a conexão com o banco é fechada mesmo se der erro.
            if (banco != null) {
                banco.fechar();
            }
        }
    }

    // ------------------------------ menu ------------------------------

    private void executarMenu() {
        boolean continuar = true;
        while (continuar) {
            System.out.println();
            System.out.println("=== SENTINELA - Detecção de Anomalias em Redes ===");
            System.out.println("1 - Cadastrar empresa");
            System.out.println("2 - Cadastrar servidor");
            System.out.println("3 - Listar empresas e servidores");
            System.out.println("4 - Excluir empresa");
            System.out.println("5 - Excluir servidor");
            System.out.println("6 - Analisar a rede de uma empresa");
            System.out.println("7 - Ver histórico de análises");
            System.out.println("8 - Relatório de anomalias da rede de uma empresa");
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
                    case "7": mostrarHistorico(); break;
                    case "8": mostrarRelatorioDeAnomalias(); break;
                    case "0": continuar = false; break;
                    default: System.out.println("Opção inválida.");
                }
            } catch (SentinelaException e) {
                // Um único catch para toda a família: cadastro inválido ou erro de banco.
                System.out.println("[ERRO] " + e.getMessage());
            } catch (IllegalArgumentException e) {
                System.out.println("[ERRO] " + e.getMessage());
            }
        }
        System.out.println("Sentinela encerrado.");
    }

    // ------------------------------ cadastro ------------------------------

    private void cadastrarEmpresa() throws SentinelaException {
        // O construtor de Empresa valida os dados e lança CadastroInvalidoException se algo estiver errado.
        Empresa empresa = new Empresa(lerTexto("Nome da empresa"), lerTexto("CNPJ"),
                lerTexto("Nome do responsável"), lerTexto("E-mail do responsável"));
        int id = banco.cadastrarEmpresa(empresa);
        System.out.println("Empresa cadastrada com o id " + id + ".");
    }

    private void cadastrarServidor() throws SentinelaException {
        listarEmpresas();
        Servidor servidor = new Servidor(lerInteiro("Id da empresa dona do servidor"),
                lerTexto("Nome do servidor"), lerTexto("Endereço IP"));
        int id = banco.cadastrarServidor(servidor);
        System.out.println("Servidor cadastrado com o id " + id + ".");
    }

    private void listarEmpresas() throws SentinelaException {
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

    private void excluirEmpresa() throws SentinelaException {
        listarEmpresas();
        int id = lerInteiro("Id da empresa a excluir (os servidores e análises dela também serão apagados)");
        System.out.println(banco.excluirEmpresa(id) ? "Empresa excluída." : "Não existe empresa com esse id.");
    }

    private void excluirServidor() throws SentinelaException {
        listarEmpresas();
        int id = lerInteiro("Id do servidor a excluir");
        System.out.println(banco.excluirServidor(id) ? "Servidor excluído." : "Não existe servidor com esse id.");
    }

    /** Se o banco estiver vazio, cadastra uma empresa fictícia para a demonstração funcionar de cara. */
    private void cadastrarExemploSeVazio() throws SentinelaException {
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

    // ------------------------------ análise ------------------------------

    /** Monta a lista de detectores com os limites usados pelo sistema. */
    private List<Detector> criarDetectores() {
        List<Detector> detectores = new ArrayList<>();
        detectores.add(new DetectorSynFlood(1000, 100));
        detectores.add(new DetectorPortScan(3000, 20));
        detectores.add(new DetectorPortaSuspeita());
        detectores.add(new DetectorTamanhoAnormal(1500));
        return detectores;
    }

    /**
     * Mostra as empresas, pergunta o id e devolve a empresa escolhida.
     *
     * @return a empresa, ou null se não existir empresa com o id digitado
     */
    private Empresa escolherEmpresa(String pergunta) throws SentinelaException {
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

    private void analisar() throws SentinelaException {
        Empresa empresa = escolherEmpresa("Id da empresa a analisar");
        if (empresa == null) {
            return;
        }
        System.out.println("De onde vem o tráfego?");
        System.out.println("  1 - Simulado (ataques de exemplo)");
        System.out.println("  2 - Arquivo de captura .pcap (Wireshark)");
        String opcaoFonte = lerTexto("Fonte");

        // As duas fontes são guardadas na mesma variável do tipo da INTERFACE.
        FonteDeTrafego fonte;
        if (opcaoFonte.equals("2")) {
            // Tira as aspas que o Windows põe em "Copiar como caminho".
            String caminho = lerTexto("Caminho do arquivo .pcap").replace("\"", "");
            fonte = new LeitorPcap(Paths.get(caminho));
        } else {
            fonte = new SimuladorTrafego(empresa.getServidores(), PACOTES_POR_ANALISE);
        }
        // POLIMORFISMO: a mesma chamada simula ou lê o arquivo, conforme o objeto.
        List<PacoteRede> pacotes = fonte.obterPacotes();
        if (pacotes.isEmpty()) {
            System.out.println("Nenhum pacote IPv4 com TCP ou ICMP encontrado (" + fonte.descrever() + ").");
            return;
        }
        boolean aoVivo = lerTexto("Mostrar o tráfego ao vivo na tela? (s/n)").equalsIgnoreCase("s");
        List<Detector> detectores = criarDetectores();
        MotorDeteccao motor = new MotorDeteccao(detectores);
        // Os dois destinos dos alertas. Para o motor, os dois são apenas "Notificador".
        motor.adicionarNotificador(new NotificadorConsole());
        motor.adicionarNotificador(banco);
        if (aoVivo) {
            motor.setMonitor(new MonitorAoVivo(INTERVALO_AO_VIVO));
        }

        System.out.println();
        System.out.println("Analisando " + pacotes.size() + " pacotes para a empresa " + empresa.getNome()
                + " (" + fonte.descrever() + ")...");
        banco.iniciarAnalise(empresa);
        motor.executar(pacotes);
        int totalDeAnomalias = motor.getAnomalias().size();
        banco.finalizarAnalise(pacotes.size(), totalDeAnomalias);

        System.out.println();
        System.out.println("---------------- RESUMO ----------------");
        System.out.println("Pacotes analisados: " + pacotes.size());
        System.out.println("Anomalias         : " + totalDeAnomalias + " (salvas no banco de dados)");
        for (Detector detector : detectores) {
            System.out.println("  - " + detector.getNome() + ": inspecionou " + detector.getPacotesInspecionados()
                    + " pacotes, " + detector.getAnomaliasGeradas() + " anomalia(s)");
        }
    }

    private void mostrarHistorico() throws SentinelaException {
        System.out.println();
        System.out.println("------- ÚLTIMAS ANÁLISES -------");
        List<String> analises = banco.listarAnalises(10);
        if (analises.isEmpty()) {
            System.out.println("Nenhuma análise feita ainda. Use a opção 6.");
            return;
        }
        for (String linha : analises) {
            System.out.println(linha);
        }


        System.out.println();
        System.out.println("------- ANOMALIAS DA ÚLTIMA ANÁLISE (mais graves primeiro) -------");
        List<Anomalia> anomalias = banco.listarAnomaliasDaUltimaAnalise();
        // Ordena usando a ordem natural definida em Anomalia.compareTo.
        Collections.sort(anomalias);
        for (Anomalia anomalia : anomalias) {
            System.out.println(anomalia);
        }
    }

    /** Opção 8: tudo o que já foi detectado na rede de uma empresa, agrupado de três formas. */
    private void mostrarRelatorioDeAnomalias() throws SentinelaException {
        Empresa empresa = escolherEmpresa("Id da empresa");
        if (empresa == null) {
            return;
        }
        List<Anomalia> anomalias = banco.listarAnomaliasDaEmpresa(empresa.getId());

        System.out.println();
        System.out.println("=============== ANOMALIAS DA REDE: " + empresa.getNome() + " ===============");
        System.out.println("Análises feitas: " + banco.contarAnalises(empresa.getId())
                + " | anomalias registradas: " + anomalias.size());
        if (anomalias.isEmpty()) {
            System.out.println("Nenhuma anomalia registrada para esta empresa. Use a opção 6.");
            return;
        }

        imprimirContagem("POR TIPO DE ATAQUE", banco.contarPorTipo(empresa.getId()));
        imprimirContagem("POR IP DE ORIGEM (quem atacou)", banco.contarPorIpAtacante(empresa.getId()));
        imprimirContagem("POR SERVIDOR (quem foi atacado)", banco.contarPorServidor(empresa.getId()));

        System.out.println();
        System.out.println("------- TODAS AS ANOMALIAS (mais graves primeiro) -------");
        Collections.sort(anomalias); // usa Anomalia.compareTo
        for (Anomalia anomalia : anomalias) {
            System.out.println(anomalia);
        }
    }

    /** Imprime um agrupamento do relatório com uma barra de "#" proporcional ao total. */
    private void imprimirContagem(String titulo, Map<String, Integer> contagem) {
        System.out.println();
        System.out.println("------- " + titulo + " -------");
        int maior = 1;
        for (int total : contagem.values()) {
            maior = Math.max(maior, total);
        }
        for (Map.Entry<String, Integer> item : contagem.entrySet()) {
            int tamanhoDaBarra = Math.max(1, item.getValue() * 30 / maior);
            System.out.printf("  %-36s %3d  %s%n", item.getKey(), item.getValue(), "#".repeat(tamanhoDaBarra));
        }
    }

    // ------------------------------ teclado ------------------------------

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
