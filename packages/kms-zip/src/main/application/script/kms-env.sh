#!/bin/bash

#
# This script contains only the steps needed to load the KMS environment
# variables. Usage:
#
# source kms-env.sh (default settings and load custom settings from default location)
#
# source kms-env.sh /path/to/file.env
#
# source kms-env.sh /path/to/env.dir
#

# configure application directory layout with defaults
export KMS_HOME=${KMS_HOME:-/opt/kms}
export KMS_CONFIGURATION=${KMS_CONFIGURATION:-$KMS_HOME/configuration}
export KMS_FEATURES=${KMS_FEATURES:-$KMS_HOME/features}
export KMS_JAVA=${KMS_JAVA:-$KMS_HOME/java}
export KMS_BIN=${KMS_BIN:-$KMS_HOME/bin}
export KMS_REPOSITORY=${KMS_REPOSITORY:-$KMS_HOME/repository}
export KMS_LOGS=${KMS_LOGS:-$KMS_HOME/logs}
export KMS_HTTP_LOG_FILE=${KMS_HTTP_LOG_FILE:-$KMS_LOGS/http.log}

###################################################################################################


# load environment variables; these override any existing environment variables.
# the idea is that if someone wants to override these, they must have write
# access to the environment files that we load here. 
KMS_ENV=${KMS_ENV:-$KMS_HOME/env}
if [ -n "$1" ]; then
    KMS_ENV="$1"
fi
if [ -e $KMS_ENV ]; then
    env_files=$(find $KMS_ENV -type f)
    # echo "loading: $env_files" >&2
    for env_file in $env_files; do
    if [ -n "$env_file" ] && [ -f "$env_file" ]; then
        source $env_file
        env_file_exports=$(cat $env_file | grep -E '^[A-Z0-9_]+\s*=' | cut -d = -f 1)
        if [ -n "$env_file_exports" ]; then eval export $env_file_exports; fi
    fi
    done
    unset env_files env_file_exports
fi

###################################################################################################


# stored master password
if [ -z "$KMS_PASSWORD" ] && [ -f $KMS_CONFIGURATION/.kms_password ]; then
  export KMS_PASSWORD=$(cat $KMS_CONFIGURATION/.kms_password)
fi


###################################################################################################

# java configuration
#Adding log4j configuration file to avoid log4j warnings during installation of kms
export JAVA_OPTS=${JAVA_OPTS:-"-Dlogback.configurationFile=$KMS_CONFIGURATION/logback.xml -Dlog4j.configuration=file:$KMS_CONFIGURATION/log4j.properties -Djdk.tls.client.protocols=TLSv1.2 -Dhttps.protocols=TLSv1.2 -Djava.net.preferIPv4Stack=true"}
#export JAVA_OPTS=${JAVA_OPTS:-"-Dlogback.configurationFile=$KMS_CONFIGURATION/logback.xml -Djdk.tls.client.protocols=TLSv1.2 -Dhttps.protocols=TLSv1.2 -Djava.net.preferIPv4Stack=true"}
# java command
if [ -z "$JAVA_CMD" ]; then
  if [ -n "$JAVA_HOME" ]; then
    JAVA_CMD=$(find $JAVA_HOME -type f -name java | head -n 1)
  else
    JAVA_CMD=`which java`
  fi
fi

# generated variables; look for common jars and feature-specific jars
JARS=$(ls -1 $KMS_JAVA/*.jar $KMS_HOME/features/*/java/*.jar)
CLASSPATH=$(echo $JARS | tr ' ' ':')

# the classpath is long and if we use the java -cp option we will not be
# able to see the full command line in ps because the output is normally
# truncated at 4096 characters. so we export the classpath to the environment
export CLASSPATH JAVA_CMD

#env | grep -v -E '^PWD=|^SHLVL=|^_='
export -n PWD OLDPWD SHLVL
export 
