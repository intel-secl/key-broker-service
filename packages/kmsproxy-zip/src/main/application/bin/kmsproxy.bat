@echo off

REM Developers can start KMS directly from build directory by setting
REM KMSPROXY_FS_JAVA=C:\path\to\dcg_security-kms\packages\kms\target\feature\java

SETLOCAL ENABLEEXTENSIONS
IF NOT %1 == generate-password (
IF NOT DEFINED KMSPROXY_PASSWORD ECHO MUST SET KMSPROXY_PASSWORD && EXIT /B 1
)
IF NOT DEFINED KMSPROXY_HOME SET KMSPROXY_HOME=C:\kms-proxy
IF NOT DEFINED KMSPROXY_FS_JAVA SET KMSPROXY_FS_JAVA=%KMSPROXY_HOME%\java
IF NOT DEFINED JVM_ARGS SET JVM_ARGS=-Xms128m -Xmx2048m -XX:MaxPermSize=128m -Dlogback.configurationFile=%KMSPROXY_HOME%\configuration\logback.xml
ENDLOCAL

ECHO KMSPROXY_HOME=%KMSPROXY_HOME%
ECHO KMSPROXY_FS_JAVA=%KMSPROXY_FS_JAVA%
ECHO JVM_ARGS=%JVM_ARGS%

java %JVM_ARGS% -cp %KMSPROXY_FS_JAVA%/* com.intel.mtwilson.launcher.console.Main %*
