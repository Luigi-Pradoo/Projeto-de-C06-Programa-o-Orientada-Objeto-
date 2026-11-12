#!/bin/sh
# Sentinela - compila e executa o projeto no Linux/macOS.
# Uso: ./executar.sh
cd "$(dirname "$0")" || exit 1
rm -rf out
javac -encoding UTF-8 -d out -cp lib/sqlite-jdbc-3.47.1.0.jar -sourcepath src/main/java src/main/java/br/inatel/sentinela/Principal.java || exit 1
java -cp "out:lib/sqlite-jdbc-3.47.1.0.jar" br.inatel.sentinela.Principal "$@"
