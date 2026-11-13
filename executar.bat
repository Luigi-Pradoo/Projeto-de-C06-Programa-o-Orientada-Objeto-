@echo off
REM ============================================================
REM  NetGuard - compila e executa o projeto no Windows.
REM  Uso: de dois cliques neste arquivo, ou no PowerShell/CMD:
REM      .\executar.bat
REM ============================================================
chcp 65001 > nul
cd /d "%~dp0"

where javac > nul 2> nul
if errorlevel 1 (
    echo [ERRO] O JDK nao foi encontrado. Instale o JDK 17 ou mais novo e marque "Add to PATH".
    pause
    exit /b 1
)

echo Compilando...
if exist out rmdir /s /q out
REM -sourcepath: a partir da classe Principal, o javac acha e compila todas as outras.
javac -encoding UTF-8 -d out -cp "lib\sqlite-jdbc-3.47.1.0.jar" -sourcepath src\main\java src\main\java\br\inatel\netguard\Principal.java
if errorlevel 1 (
    echo [ERRO] A compilacao falhou.
    pause
    exit /b 1
)

java -Dfile.encoding=UTF-8 -Dstdout.encoding=UTF-8 -cp "out;lib\sqlite-jdbc-3.47.1.0.jar" br.inatel.netguard.Principal %*
pause
