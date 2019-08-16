#!/bin/sh

# KMSPROXY install script
# Outline:
# 1. look for ~/kmsproxy.env and source it if it's there
# 2. source the "functions.sh" file:  mtwilson-linux-util-3.0-SNAPSHOT.sh
# 3. determine if we are installing as root or non-root user; set paths
# 4. detect java
# 5. if java not installed, and we have it bundled, install it
# 6. unzip kmsproxy archive kmsproxy-zip-0.1-SNAPSHOT.zip into /opt/kmsproxy, overwrite if any files already exist
# 7. link /usr/local/bin/kmsproxy -> /opt/kmsproxy/bin/kmsproxy, if not already there
# 8. add kmsproxy to startup services
# 9. look for KMSPROXY_PASSWORD environment variable; if not present print help message and exit:
#    KMSPROXY requires a master password
#    to generate a password run "export KMSPROXY_PASSWORD=$(kmsproxy generate-password) && echo KMSPROXY_PASSWORD=$KMSPROXY_PASSWORD"
#    you must store this password in a safe place
#    losing the master password will result in data loss
# 10. kmsproxy setup
# 11. kmsproxy start

#####

# default settings
# note the layout setting is used only by this script
# and it is not saved or used by the app script
KMSPROXY_HOME=${KMSPROXY_HOME:-/opt/kmsproxy}
KMSPROXY_LAYOUT=${KMSPROXY_LAYOUT:-home}

# the env directory is not configurable; it is defined as KMSPROXY_HOME/env and the
# administrator may use a symlink if necessary to place it anywhere else
export KMSPROXY_ENV=$KMSPROXY_HOME/env

# the env directory is not configurable; it is defined as KMSPROXY_HOME/env and the
# administrator may use a symlink if necessary to place it anywhere else
export KMSPROXY_ENV=$KMSPROXY_HOME/env

# load application environment variables if already defined
if [ -d $KMSPROXY_ENV ]; then
  KMSPROXY_ENV_FILES=$(ls -1 $KMSPROXY_ENV/*)
  for env_file in $KMSPROXY_ENV_FILES; do
    . $env_file
    env_file_exports=$(cat $env_file | grep -E '^[A-Z0-9_]+\s*=' | cut -d = -f 1)
    if [ -n "$env_file_exports" ]; then eval export $env_file_exports; fi
  done
fi

# load installer environment file, if present
if [ -f ~/kmsproxy.env ]; then
  echo "Loading environment variables from $(cd ~ && pwd)/kmsproxy.env"
  . ~/kmsproxy.env
  env_file_exports=$(cat ~/kmsproxy.env | grep -E '^[A-Z0-9_]+\s*=' | cut -d = -f 1)
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
  # create a kmsproxy user if there isn't already one created
  KMSPROXY_USERNAME=${KMSPROXY_USERNAME:-kmsproxy}
  if ! getent passwd $KMSPROXY_USERNAME 2>&1 >/dev/null; then
    useradd --comment "Mt Wilson KMSPROXY" --home $KMSPROXY_HOME --system --shell /bin/false $KMSPROXY_USERNAME
    usermod --lock $KMSPROXY_USERNAME
    # note: to assign a shell and allow login you can run "usermod --shell /bin/bash --unlock $KMSPROXY_USERNAME"
  fi
else
  # already running as kmsproxy user
  KMSPROXY_USERNAME=$(whoami)
  echo_warning "Running as $KMSPROXY_USERNAME; if installation fails try again as root"
  if [ ! -w "$KMSPROXY_HOME" ] && [ ! -w $(dirname $KMSPROXY_HOME) ]; then
    export KMSPROXY_HOME=$(cd ~ && pwd)
  fi
fi

# if an existing kmsproxy is already running, stop it while we install
if which kmsproxy; then
  kmsproxy stop
fi

# define application directory layout
if [ "$KMSPROXY_LAYOUT" == "linux" ]; then
  export KMSPROXY_CONFIGURATION=${KMSPROXY_CONFIGURATION:-/etc/kmsproxy}
  export KMSPROXY_REPOSITORY=${KMSPROXY_REPOSITORY:-/var/opt/kmsproxy}
  export KMSPROXY_LOGS=${KMSPROXY_LOGS:-/var/log/kmsproxy}
elif [ "$KMSPROXY_LAYOUT" == "home" ]; then
  export KMSPROXY_CONFIGURATION=${KMSPROXY_CONFIGURATION:-$KMSPROXY_HOME/configuration}
  export KMSPROXY_REPOSITORY=${KMSPROXY_REPOSITORY:-$KMSPROXY_HOME/repository}
  export KMSPROXY_LOGS=${KMSPROXY_LOGS:-$KMSPROXY_HOME/logs}
fi
export KMSPROXY_BIN=${KMSPROXY_BIN:-$KMSPROXY_HOME/bin}
export KMSPROXY_JAVA=${KMSPROXY_JAVA:-$KMSPROXY_HOME/java}

# note that the env dir is not configurable; it is defined as "env" under home
export KMSPROXY_ENV=$KMSPROXY_HOME/env

kmsproxy_backup_configuration() {
  if [ -n "$KMSPROXY_CONFIGURATION" ] && [ -d "$KMSPROXY_CONFIGURATION" ]; then
    datestr=`date +%Y%m%d.%H%M`
    backupdir=/var/backup/kmsproxy.configuration.$datestr
    cp -r $KMSPROXY_CONFIGURATION $backupdir
  fi
}

kmsproxy_backup_repository() {
  if [ -n "$KMSPROXY_REPOSITORY" ] && [ -d "$KMSPROXY_REPOSITORY" ]; then
    datestr=`date +%Y%m%d.%H%M`
    backupdir=/var/backup/kmsproxy.repository.$datestr
    cp -r $KMSPROXY_REPOSITORY $backupdir
  fi
}

# backup current configuration and data, if they exist
kmsproxy_backup_configuration
kmsproxy_backup_repository

# create application directories (chown will be repeated near end of this script, after setup)
for directory in $KMSPROXY_HOME $KMSPROXY_CONFIGURATION $KMSPROXY_ENV $KMSPROXY_REPOSITORY $KMSPROXY_LOGS; do
  mkdir -p $directory
  chown -R $KMSPROXY_USERNAME:$KMSPROXY_USERNAME $directory
  chmod 700 $directory
done


# store directory layout in env file
echo "# $(date)" > $KMSPROXY_ENV/kmsproxy-layout
echo "export KMSPROXY_HOME=$KMSPROXY_HOME" >> $KMSPROXY_ENV/kmsproxy-layout
echo "export KMSPROXY_CONFIGURATION=$KMSPROXY_CONFIGURATION" >> $KMSPROXY_ENV/kmsproxy-layout
echo "export KMSPROXY_JAVA=$KMSPROXY_JAVA" >> $KMSPROXY_ENV/kmsproxy-layout
echo "export KMSPROXY_BIN=$KMSPROXY_BIN" >> $KMSPROXY_ENV/kmsproxy-layout
echo "export KMSPROXY_REPOSITORY=$KMSPROXY_REPOSITORY" >> $KMSPROXY_ENV/kmsproxy-layout
echo "export KMSPROXY_LOGS=$KMSPROXY_LOGS" >> $KMSPROXY_ENV/kmsproxy-layout
if [ -n "$KMSPROXY_PID_FILE" ]; then echo "export KMSPROXY_PID_FILE=$KMSPROXY_PID_FILE" >> $KMSPROXY_ENV/kmsproxy-layout; fi

# store kmsproxy username in env file
echo "# $(date)" > $KMSPROXY_ENV/kmsproxy-username
echo "export KMSPROXY_USERNAME=$KMSPROXY_USERNAME" >> $KMSPROXY_ENV/kmsproxy-username

# store log level in env file, if it's set
if [ -n "$KMXPROXY_LOG_LEVEL" ]; then
  echo "# $(date)" > $KMSPROXY_ENV/kmsproxy-logging
  echo "export KMXPROXY_LOG_LEVEL=$KMXPROXY_LOG_LEVEL" >> $KMSPROXY_ENV/kmsproxy-logging
fi

# store the auto-exported environment variables in env file
# to make them available after the script uses sudo to switch users;
# we delete that file later
echo "# $(date)" > $KMSPROXY_ENV/kmsproxy-setup
for env_file_var_name in $env_file_exports
do
  eval env_file_var_value="\$$env_file_var_name"
  echo "export $env_file_var_name=$env_file_var_value" >> $KMSPROXY_ENV/kmsproxy-setup
done

# kms requires java 1.8 or later
echo "Installing Java..."
JAVA_REQUIRED_VERSION=${JAVA_REQUIRED_VERSION:-1.8}
java_install_openjdk
JAVA_CMD=$(type -p java | xargs readlink -f)
JAVA_HOME=$(dirname $JAVA_CMD | xargs dirname | xargs dirname)
JAVA_REQUIRED_VERSION=$(java -version 2>&1 | head -n 1 | awk -F '"' '{print $2}')
echo "# $(date)" > $KMSPROXY_ENV/kmsproxy-java
echo "export JAVA_HOME=$JAVA_HOME" >> $KMSPROXY_ENV/kmsproxy-java
echo "export JAVA_CMD=$JAVA_CMD" >> $KMSPROXY_ENV/kmsproxy-java
echo "export JAVA_REQUIRED_VERSION=$JAVA_REQUIRED_VERSION" >> $KMSPROXY_ENV/kmsproxy-java

# make sure unzip is installed
KMSPROXY_YUM_PACKAGES="zip unzip"
KMSPROXY_APT_PACKAGES="zip unzip"
KMSPROXY_YAST_PACKAGES="zip unzip"
KMSPROXY_ZYPPER_PACKAGES="zip unzip"
auto_install "Installer requirements" "KMSPROXY"

KMSPROXY_PORT_HTTP=${KMSPROXY_PORT_HTTP:-${JETTY_PORT:-80}}
KMSPROXY_PORT_HTTPS=${KMSPROXY_PORT_HTTPS:-${JETTY_SECURE_PORT:-443}}

# delete existing java files, to prevent a situation where the installer copies
# a newer file but the older file is also there
if [ -d $KMSPROXY_HOME/java ]; then
  rm $KMSPROXY_HOME/java/*.jar
fi

# extract kmsproxy  (kmsproxy-zip-0.1-SNAPSHOT.zip)
echo "Extracting application..."
KMSPROXY_ZIPFILE=`ls -1 kmsproxy-*.zip 2>/dev/null | head -n 1`
unzip -DDoq $KMSPROXY_ZIPFILE -d $KMSPROXY_HOME

# if the configuration folder was specified, move the default configurations there
# that were extracted from the zip
if [ "$KMSPROXY_CONFIGURATION" != "$KMSPROXY_HOME/configuration" ]; then
  # only copy files that don't already exist in destination, to avoid overwriting
  # user's prior edits
  cp -n $KMSPROXY_HOME/configuration/* $KMSPROXY_CONFIGURATION/
  # in the future, if we have a version variable we could move the remaining
  # files into the configuration directory in a versioned subdirectory.
  # finally, remove the configuration folder so user will not be confused about
  # where to edit. 
  rm -rf $KMSPROXY_HOME/configuration
fi


# copy utilities script file to application folder
cp $UTIL_SCRIPT_FILE $KMSPROXY_HOME/bin/functions.sh

# set permissions
chown -R $KMSPROXY_USERNAME:$KMSPROXY_USERNAME $KMSPROXY_HOME
chmod 755 $KMSPROXY_HOME/bin/*

# link /usr/local/bin/kmsproxy -> /opt/kmsproxy/bin/kmsproxy
EXISTING_KMSPROXY_COMMAND=`which kmsproxy`
if [ -z "$EXISTING_KMSPROXY_COMMAND" ]; then
  ln -s $KMSPROXY_HOME/bin/kmsproxy.sh /usr/local/bin/kmsproxy
fi


# register linux startup script
if [ "$KMSPROXY_USERNAME" == "root" ]; then
  register_startup_script $KMSPROXY_HOME/bin/kmsproxy.sh kmsproxy
else
  echo "@reboot $KMSPROXY_HOME/bin/kmsproxy.sh start" > $KMSPROXY_CONFIGURATION/crontab
  crontab -u $KMSPROXY_USERNAME -l | cat - $KMSPROXY_CONFIGURATION/crontab | crontab -u $KMSPROXY_USERNAME -
fi

# setup the kmsproxy, unless the NOSETUP variable is defined
if [ -z "$KMSPROXY_NOSETUP" ]; then

  # the master password is required
  if [ -z "$KMSPROXY_PASSWORD" ] && [ ! -f $KMSPROXY_CONFIGURATION/.kmsproxy_password ]; then
    touch $KMSPROXY_CONFIGURATION/.kmsproxy_password
    chown $KMSPROXY_USERNAME:$KMSPROXY_USERNAME $KMSPROXY_CONFIGURATION/.kmsproxy_password
    kmsproxy generate-password > $KMSPROXY_CONFIGURATION/.kmsproxy_password
  fi

  kmsproxy config mtwilson.extensions.fileIncludeFilter.contains "${MTWILSON_EXTENSIONS_FILEINCLUDEFILTER_CONTAINS:-mtwilson,kms,jersey-media-multipart}" >/dev/null
  kmsproxy config mtwilson.extensions.packageIncludeFilter.startsWith "${MTWILSON_EXTENSIONS_PACKAGEINCLUDEFILTER_STARTSWITH:-com.intel,org.glassfish.jersey.media.multipart}" >/dev/null

  kmsproxy config jetty.port $KMSPROXY_PORT_HTTP >/dev/null
  kmsproxy config jetty.secure.port $KMSPROXY_PORT_HTTPS >/dev/null

  kmsproxy config mtwilson.tls.cert.sha256 $MTWILSON_TLS_CERT_SHA256 >/dev/null
  kmsproxy config mtwilson.api.username $MTWILSON_API_USERNAME >/dev/null
  kmsproxy config mtwilson.api.password $MTWILSON_API_PASSWORD >/dev/null
  kmsproxy config mtwilson.api.url $MTWILSON_API_URL >/dev/null
  kmsproxy setup

  # temporary fix for bug #5008
  echo >> $KMSPROXY_CONFIGURATION/extensions.cache
  echo org.glassfish.jersey.media.multipart.MultiPartFeature >> $KMSPROXY_CONFIGURATION/extensions.cache
fi

# delete the temporary setup environment variables file
rm -f $KMSPROXY_ENV/kmsproxy-setup

# ensure the kmsproxy owns all the content created during setup
for directory in $KMSPROXY_HOME $KMSPROXY_CONFIGURATION  $KMSPROXY_JAVA $KMSPROXY_BIN $KMSPROXY_ENV $KMSPROXY_REPOSITORY $KMSPROXY_LOGS; do
  chown -R $KMSPROXY_USERNAME:$KMSPROXY_USERNAME $directory
done

# start the server, unless the NOSETUP variable is defined
if [ -z "$KMSPROXY_NOSETUP" ]; then kmsproxy start; fi
