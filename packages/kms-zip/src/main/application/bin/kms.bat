@echo off

REM Developers can start KMS directly from build directory by setting
REM KMS_FS_JAVA=C:\path\to\dcg_security-kms\packages\kms\target\feature\java

REM SETLOCAL ENABLEEXTENSIONS
IF NOT DEFINED KMS_PASSWORD ECHO MUST SET KMS_PASSWORD && EXIT /B 1
IF NOT DEFINED KMS_HOME SET KMS_HOME=C:\kms
IF NOT DEFINED KMS_FS_JAVA SET KMS_FS_JAVA=%KMS_HOME%\java
IF NOT DEFINED JVM_ARGS SET JVM_ARGS=-Xms128m -Xmx2048m -XX:MaxPermSize=128m -Dlogback.configurationFile=%KMS_HOME%\configuration\logback.xml
REM ENDLOCAL

ECHO KMS_HOME=%KMS_HOME%
ECHO KMS_FS_JAVA=%KMS_FS_JAVA%
ECHO JVM_ARGS=%JVM_ARGS%

java %JVM_ARGS% -cp %KMS_FS_JAVA%/* com.intel.mtwilson.launcher.console.Main %*
