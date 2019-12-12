#!/bin/sh

# KMS install script
# Outline:
# 1. look for ~/kms.env and source it if it's there
# 2. source the "functions.sh" file:  mtwilson-linux-util-3.0-SNAPSHOT.sh
# 3. determine if we are installing as root or non-root user; set paths
# 4. detect java
# 5. if java not installed, and we have it bundled, install it
# 6. unzip kms archive kms-zip-0.1-SNAPSHOT.zip into /opt/kms, overwrite if any files already exist
# 7. link /usr/local/bin/kms -> /opt/kms/bin/kms, if not already there
# 8. add kms to startup services
# 9. look for KMS_PASSWORD environment variable; if not present print help message and exit:
#    KMS requires a master password
#    to generate a password run "export KMS_PASSWORD=$(kms generate-password) && echo KMS_PASSWORD=$KMS_PASSWORD"
#    you must store this password in a safe place
#    losing the master password will result in data loss
# 10. kms init
# 11. kms start

#####

# configure application directory layout with defaults
export LOG_ROTATION_PERIOD=${LOG_ROTATION_PERIOD:-weekly}
export LOG_COMPRESS=${LOG_COMPRESS:-compress}
export LOG_DELAYCOMPRESS=${LOG_DELAYCOMPRESS:-delaycompress}
export LOG_COPYTRUNCATE=${LOG_COPYTRUNCATE:-copytruncate}
export LOG_SIZE=${LOG_SIZE:-1G}
export LOG_OLD=${LOG_OLD:-12}
export KMS_PORT_HTTP=${KMS_PORT_HTTP:-9442}
export KMS_PORT_HTTPS=${KMS_PORT_HTTPS:-9443}
export KMS_HOME=${KMS_HOME:-/opt/kms}
export KMS_ENV=${KMS_ENV:-$KMS_HOME/env}
export KMS_CONFIGURATION=${KMS_CONFIGURATION:-$KMS_HOME/configuration}
export KMS_FEATURES=${KMS_FEATURES:-$KMS_HOME/features}
export KMS_JAVA=${KMS_JAVA:-$KMS_HOME/java}
export KMS_BIN=${KMS_BIN:-$KMS_HOME/bin}
export KMS_SCRIPT=${KMS_SCRIPT:-$KMS_HOME/script}
export KMS_REPOSITORY=${KMS_REPOSITORY:-$KMS_HOME/repository}
export KMS_LOGS=${KMS_LOGS:-$KMS_HOME/logs}
export KMS_NOSETUP=${KMS_NOSETUP:-false}

SUPER_USER=root

# load application environment variables if already defined
if [ -d $KMS_ENV ]; then
  KMS_ENV_FILES=$(ls -1 $KMS_ENV/*)
  for env_file in $KMS_ENV_FILES; do
    . $env_file
    env_file_exports=$(cat $env_file | grep -E '^[A-Z0-9_]+\s*=' | cut -d = -f 1)
    if [ -n "$env_file_exports" ]; then eval export $env_file_exports; fi
  done
fi

# load installer environment file, if present
if [ -f ~/kms.env ]; then
  echo "Loading environment variables from $(cd ~ && pwd)/kms.env"
  . ~/kms.env
  env_file_exports=$(cat ~/kms.env | grep -E '^[A-Z0-9_]+\s*=' | cut -d = -f 1)
  if [ -n "$env_file_exports" ]; then eval export $env_file_exports; fi
else
  echo "No environment file"
fi

# functions script (mtwilson-linux-util-3.0-SNAPSHOT.sh) is required
# we use the following functions:
# java_detect java_ready_report 
# echo_failure echo_warning
# register_startup_script
UTIL_SCRIPT_FILE=`ls -1 mtwilson-linux-util-*.sh | head -n 1`
if [ -n "$UTIL_SCRIPT_FILE" ] && [ -f "$UTIL_SCRIPT_FILE" ]; then
  . $UTIL_SCRIPT_FILE
fi

# determine if we are installing as root or non-root
if [ "$(whoami)" == "root" ]; then
  # create a kms user if there isn't already one created
  KMS_USERNAME=${KMS_USERNAME:-kms}
  if ! getent passwd $KMS_USERNAME 2>&1 >/dev/null; then
    useradd --comment "Mt Wilson KMS" --home $KMS_HOME --system --shell /bin/false $KMS_USERNAME
    usermod --lock $KMS_USERNAME
    # note: to assign a shell and allow login you can run "usermod --shell /bin/bash --unlock $KMS_USERNAME"
  fi
else
  # already running as kms user
  KMS_USERNAME=$(whoami)
  echo_warning "Running as $KMS_USERNAME; if installation fails try again as root"
  if [ ! -w "$KMS_HOME" ] && [ ! -w $(dirname $KMS_HOME) ]; then
    export KMS_HOME=$(cd ~ && pwd)
  fi
fi

# if kms is already installed, stop it while we upgrade/reinstall
if which kms 2>/dev/null; then
  kms stop
fi


kms_backup_configuration() {
  if [ -n "$KMS_CONFIGURATION" ] && [ -d "$KMS_CONFIGURATION" ]; then
    datestr=`date +%Y%m%d.%H%M`
    backupdir=$KMS_REPOSITORY/backup/kms.configuration.$datestr
    mkdir -p $backupdir
    cp -r $KMS_CONFIGURATION/* $backupdir/
  fi
}

# backup current configuration, if they exist
kms_backup_configuration

# create application directories (chown will be repeated near end of this script, after setup)
for directory in $KMS_HOME $KMS_CONFIGURATION $KMS_FEATURES $KMS_ENV $KMS_REPOSITORY $KMS_LOGS; do
  mkdir -p $directory
  chown -R $KMS_USERNAME:$KMS_USERNAME $directory
  chmod 700 $directory
done


# store directory layout in env file
echo "# $(date)" > $KMS_ENV/kms-layout
echo "export KMS_HOME=$KMS_HOME" >> $KMS_ENV/kms-layout
echo "export KMS_CONFIGURATION=$KMS_CONFIGURATION" >> $KMS_ENV/kms-layout
echo "export KMS_FEATURES=$KMS_FEATURES" >> $KMS_ENV/kms-layout
echo "export KMS_JAVA=$KMS_JAVA" >> $KMS_ENV/kms-layout
echo "export KMS_BIN=$KMS_BIN" >> $KMS_ENV/kms-layout
echo "export KMS_SCRIPT=$KMS_SCRIPT" >> $KMS_ENV/kms-layout
echo "export KMS_REPOSITORY=$KMS_REPOSITORY" >> $KMS_ENV/kms-layout
echo "export KMS_LOGS=$KMS_LOGS" >> $KMS_ENV/kms-layout
if [ -n "$KMS_PID_FILE" ]; then echo "export KMS_PID_FILE=$KMS_PID_FILE" >> $KMS_ENV/kms-layout; fi

# store kms username in env file
echo "# $(date)" > $KMS_ENV/kms-username
echo "export KMS_USERNAME=$KMS_USERNAME" >> $KMS_ENV/kms-username

# store log level in env file, if it's set
if [ -n "$KMS_LOG_LEVEL" ]; then
  echo "# $(date)" > $KMS_ENV/kms-logging
  echo "export KMS_LOG_LEVEL=$KMS_LOG_LEVEL" >> $KMS_ENV/kms-logging
fi

# store the auto-exported environment variables in temporary env file
# to make them available after the script uses sudo to switch users;
# we delete that file later
echo "# $(date)" > $KMS_ENV/kms-setup
for env_file_var_name in $env_file_exports
do
  eval env_file_var_value="\$$env_file_var_name"
  echo "export $env_file_var_name=$env_file_var_value" >> $KMS_ENV/kms-setup
done

# kms requires java 1.8 or later
if [ "$IS_RPM" != "true" ]; then
  java_install_openjdk
  if [ $? -ne 0 ]; then echo_failure "Failed to install openjdk through package manager"; exit 1; fi
fi


JAVA_CMD=$(type -p java | xargs readlink -f)
JAVA_HOME=$(dirname $JAVA_CMD | xargs dirname | xargs dirname)
JAVA_REQUIRED_VERSION=$(java -version 2>&1 | head -n 1 | awk -F '"' '{print $2}')

echo "# $(date)" > $KMS_ENV/kms-java
echo "export JAVA_HOME=$JAVA_HOME" >> $KMS_ENV/kms-java
echo "export JAVA_CMD=$JAVA_CMD" >> $KMS_ENV/kms-java
echo "export JAVA_REQUIRED_VERSION=$JAVA_REQUIRED_VERSION" >> $KMS_ENV/kms-java

if [ -f "${JAVA_HOME}/jre/lib/security/java.security" ]; then
  echo "Replacing java.security file, existing file will be backed up"
  backup_file "${JAVA_HOME}/jre/lib/security/java.security"
  cp java.security "${JAVA_HOME}/jre/lib/security/java.security"
fi

# make sure unzip is installed
KMS_YUM_PACKAGES="zip unzip"
KMS_APT_PACKAGES="zip unzip"
KMS_YAST_PACKAGES="zip unzip"
KMS_ZYPPER_PACKAGES="zip unzip"
auto_install "Installer requirements" "KMS"

KMS_PORT_HTTP=${KMS_PORT_HTTP:-${JETTY_PORT:-80}}
KMS_PORT_HTTPS=${KMS_PORT_HTTPS:-${JETTY_SECURE_PORT:-443}}

# delete existing java files, to prevent a situation where the installer copies
# a newer file but the older file is also there
if [ -d $KMS_HOME/java ]; then
  rm $KMS_HOME/java/*.jar
fi

# extract kms  (kms-zip-0.1-SNAPSHOT.zip)
echo "Extracting application..."
KMS_ZIPFILE=`ls -1 kms-*.zip 2>/dev/null | head -n 1`
unzip -DDoq $KMS_ZIPFILE -d $KMS_HOME

# if the configuration folder was specified, move the default configurations there
# that were extracted from the zip
if [ "$KMS_CONFIGURATION" != "$KMS_HOME/configuration" ]; then
  # only copy files that don't already exist in destination, to avoid overwriting
  # user's prior edits
  cp -n $KMS_HOME/configuration/* $KMS_CONFIGURATION/
  # in the future, if we have a version variable we could move the remaining
  # files into the configuration directory in a versioned subdirectory.
  # finally, remove the configuration folder so user will not be confused about
  # where to edit. 
  rm -rf $KMS_HOME/configuration
fi

# copy utilities script file to application folder
cp $UTIL_SCRIPT_FILE $KMS_HOME/bin/functions.sh

# set permissions
chown -R $KMS_USERNAME:$KMS_USERNAME $KMS_HOME
chmod 755 $KMS_HOME/bin/*

# link /usr/local/bin/kms -> /opt/kms/bin/kms
EXISTING_KMS_COMMAND=`which kms 2>/dev/null`
if [ -z "$EXISTING_KMS_COMMAND" ]; then
  ln -s $KMS_HOME/bin/kms.sh /usr/local/bin/kms
fi
if [[ ! -h $KMS_BIN/kms ]]; then
  ln -s $KMS_BIN/kms.sh $KMS_BIN/kms
fi

# register linux startup script
if [ "$(whoami)" == "root" ]; then
  register_startup_script /usr/local/bin/kms kms
fi

# add crypto providers to java extensions
cp $KMS_JAVA/mtwilson-util-crypto-jca-*.jar $KMS_JAVA/bcprov-jdk15on-*.jar $JAVA_HOME/jre/lib/ext
chown $KMS_USERNAME:$KMS_USERNAME $JAVA_HOME/jre/lib/ext/*.jar

echo "Extracting tools..."
TOOL_ZIPFILE=$(find . -type f -name "tpm-agent-tools-dist-*.zip" 2>/dev/null | head -n 1)
if [ -n "$TOOL_ZIPFILE" ]; then
    #setup aikqverify
    aikqverify_dir=${KMS_FEATURES}/aikqverify
    mkdir -p ${aikqverify_dir}/bin
    mkdir -p ${aikqverify_dir}/data
    unzip -DDoq $TOOL_ZIPFILE
    cp tpmagent/bin/aikqverify ${aikqverify_dir}/bin/
    chmod 755 ${aikqverify_dir}/bin/aikqverify
fi

# setup the kms, unless the NOSETUP variable is set to true
if [ "$KMS_NOSETUP" = "false" ]; then
  kms init
fi

# delete the temporary setup environment variables file
rm -f $KMS_ENV/kms-setup

# ensure the kms owns all the content created during setup
for directory in $KMS_HOME $KMS_FEATURES $KMS_JAVA $KMS_BIN $KMS_ENV $KMS_REPOSITORY $KMS_LOGS; do
  chown -R $KMS_USERNAME:$KMS_USERNAME $directory
done

# Log Rotate
mkdir -p /etc/logrotate.d
if [ ! -a /etc/logrotate.d/kms ]; then
 echo "/opt/kms/logs/kms.log {
    missingok
	notifempty
	rotate $LOG_OLD
	maxsize $LOG_SIZE
    nodateext
	$LOG_ROTATION_PERIOD
	$LOG_COMPRESS
	$LOG_DELAYCOMPRESS
	$LOG_COPYTRUNCATE
}" > /etc/logrotate.d/kms
fi

#fix for task 7087
#chown -R $SUPER_USER:$SUPER_USER $KMS_CONFIGURATION
#find $KMS_CONFIGURATION -type d -exec chmod 755 {} \;
#find $KMS_CONFIGURATION -type f -exec chmod 644 {} \;

# start the server, unless the NOSETUP variable is set to true
if [ "$KMS_NOSETUP" = "false" ]; then kms start; fi
echo_success "Installation complete"
