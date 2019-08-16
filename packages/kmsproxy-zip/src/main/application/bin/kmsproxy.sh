#!/bin/bash

# chkconfig: 2345 80 30
# description: Intel Key Management Service

### BEGIN INIT INFO
# Provides:          kmsproxy
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Should-Start:      $portmap
# Should-Stop:       $portmap
# X-Start-Before:    nis
# X-Stop-After:      nis
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# X-Interactive:     true
# Short-Description: kmsproxy
# Description:       Main script to run kmsproxy commands
### END INIT INFO
DESC="KMSPROXY"
NAME=kmsproxy

# the home directory must be defined before we load any environment or
# configuration files; it is explicitly passed through the sudo command
export KMSPROXY_HOME=${KMSPROXY_HOME:-/opt/kmsproxy}
export KMSPROXY_BIN=$KMSPROXY_HOME/bin

# the env directory is not configurable; it is defined as KMSPROXY_HOME/env and the
# administrator may use a symlink if necessary to place it anywhere else
export KMSPROXY_ENV=$KMSPROXY_HOME/env

kmsproxy_load_env() {
  local env_files="$@"
  local env_file_exports
  for env_file in $env_files; do
    if [ -n "$env_file" ] && [ -f "$env_file" ]; then
      . $env_file
      env_file_exports=$(cat $env_file | grep -E '^[A-Z0-9_]+\s*=' | cut -d = -f 1)
      if [ -n "$env_file_exports" ]; then eval export $env_file_exports; fi
    fi
  done
}

if [ -z "$KMSPROXY_USERNAME" ]; then
  kmsproxy_load_env $KMSPROXY_HOME/env/kmsproxy-username
fi


###################################################################################################

# if non-root execution is specified, and we are currently root, start over; the KMSPROXY_SUDO variable limits this to one attempt
# we make an exception for the uninstall command, which may require root access to delete users and certain directories
#if [ -n "$KMSPROXY_USERNAME" ] && [ "$KMSPROXY_USERNAME" != "root" ] && [ $(whoami) == "root" ] && [ -z "$KMSPROXY_SUDO" ] && [ "$1" != "uninstall" ]; then
#  sudo -u $KMSPROXY_USERNAME KMSPROXY_HOME=$KMSPROXY_HOME KMSPROXY_PASSWORD=$KMSPROXY_PASSWORD KMSPROXY_SUDO=true $KMSPROXY_BIN/kmsproxy.sh $*
#  exit $?
#fi

###################################################################################################

# load environment variables; these may override the defaults set above and 
# also note that kmsproxy-username file is loaded twice, once before sudo and once
# here after sudo.
if [ -d $KMSPROXY_ENV ]; then
  kmsproxy_load_env $(ls -1 $KMSPROXY_ENV/*)
fi

# default directory layout follows the 'home' style
export KMSPROXY_CONFIGURATION=${KMSPROXY_CONFIGURATION:-$KMSPROXY_HOME/configuration}
export KMSPROXY_JAVA=${KMSPROXY_JAVA:-$KMSPROXY_HOME/java}
export KMSPROXY_BIN=${KMSPROXY_BIN:-$KMSPROXY_HOME/bin}
export KMSPROXY_REPOSITORY=${KMSPROXY_REPOSITORY:-$KMSPROXY_HOME/repository}
export KMSPROXY_LOGS=${KMSPROXY_LOGS:-$KMSPROXY_HOME/logs}

###################################################################################################


# load linux utility
if [ -f "$KMSPROXY_HOME/bin/functions.sh" ]; then
  . $KMSPROXY_HOME/bin/functions.sh
fi

###################################################################################################

# stored master password
if [ -z "$KMSPROXY_PASSWORD" ] && [ -f $KMSPROXY_CONFIGURATION/.kmsproxy_password ]; then
  export KMSPROXY_PASSWORD=$(cat $KMSPROXY_CONFIGURATION/.kmsproxy_password)
fi

# all other variables with defaults
KMSPROXY_HTTP_LOG_FILE=${KMSPROXY_HTTP_LOG_FILE:-$KMSPROXY_LOGS/http.log}
JAVA_REQUIRED_VERSION=${JAVA_REQUIRED_VERSION:-1.7}

#Adding log4j configuration file to avoid log4j warnings during installation of kms
JAVA_OPTS=${JAVA_OPTS:-"-Dlogback.configurationFile=$KMSPROXY_CONFIGURATION/logback.xml -Dlog4j.configuration=file:$KMSPROXY_CONFIGURATION/log4j.properties"}
#JAVA_OPTS=${JAVA_OPTS:-"-Dlogback.configurationFile=$KMSPROXY_CONFIGURATION/logback.xml"}
KMSPROXY_SETUP_FIRST_TASKS=${KMSPROXY_SETUP_FIRST_TASKS:-"filesystem update-extensions-cache-file"}
#Removing mtwilson-client task as we include mtwilson credentials in env file and those are store in kmsproxy configuration, certificates saml, root and privacy ca are not required
#KMSPROXY_SETUP_TASKS=${KMSPROXY_SETUP_TASKS:-"password-vault jetty-ports jetty-tls-keystore shiro-ssl-port mtwilson-client"}
KMSPROXY_SETUP_TASKS=${KMSPROXY_SETUP_TASKS:-"password-vault jetty-ports jetty-tls-keystore shiro-ssl-port"}

# the standard PID file location /var/run is typically owned by root;
# if we are running as non-root and the standard location isn't writable 
# then we need a different place
KMSPROXY_PID_FILE=${KMSPROXY_PID_FILE:-/var/run/kmsproxy.pid}
touch $KMSPROXY_PID_FILE >/dev/null 2>&1
if [ $? == 1 ]; then KMSPROXY_PID_FILE=$KMSPROXY_LOGS/kmsproxy.pid; fi

###################################################################################################

# java command
if [ -z "$JAVA_CMD" ]; then
  if [ -n "$JAVA_HOME" ]; then
    JAVA_CMD=$JAVA_HOME/bin/java
  else
    JAVA_CMD=`which java`
  fi
fi

# generated variables; look for common jars and feature-specific jars
JARS=$(ls -1 $KMSPROXY_JAVA/*.jar $KMSPROXY_HOME/features/*/java/*.jar)
CLASSPATH=$(echo $JARS | tr ' ' ':')

# the classpath is long and if we use the java -cp option we will not be
# able to see the full command line in ps because the output is normally
# truncated at 4096 characters. so we export the classpath to the environment
export CLASSPATH

###################################################################################################

# run a kmsproxy command
kmsproxy_run() {
  local args="$*"
  $JAVA_CMD $JAVA_OPTS com.intel.mtwilson.launcher.console.Main $args
  return $?
}

# run default set of setup tasks and check if admin user needs to be created
kmsproxy_complete_setup() {
  # run all setup tasks, don't use the force option to avoid clobbering existing
  # useful configuration files
  kmsproxy_run setup $KMSPROXY_SETUP_FIRST_TASKS
  kmsproxy_run setup $KMSPROXY_SETUP_TASKS
}

# arguments are optional, if provided they are the names of the tasks to run, in order
kmsproxy_setup() {
  local args="$*"
#  $JAVA_CMD $JAVA_OPTS com.intel.mtwilson.launcher.console.Main setup $args
  $JAVA_CMD $JAVA_OPTS com.intel.mtwilson.launcher.console.Main $args
  return $?
}

kmsproxy_start() {
    if [ -z "$KMSPROXY_PASSWORD" ]; then
      echo_failure "Master password is required; export KMSPROXY_PASSWORD"
      return 1
    fi

    # check if we're already running - don't start a second instance
    if kmsproxy_is_running; then
        echo "KMSPROXY is running"
        return 0
    fi

    prog="$JAVA_CMD"

    # the subshell allows the java process to have a reasonable current working
    # directory without affecting the user's working directory. 
    # the last background process pid $! must be stored from the subshell.
    (
      cd $KMSPROXY_HOME
      $prog $JAVA_OPTS com.intel.mtwilson.launcher.console.Main jetty-start >>$KMSPROXY_HTTP_LOG_FILE 2>&1 &
      echo $! > $KMSPROXY_PID_FILE
    )
    if kmsproxy_is_running; then
      echo_success "Started KMSPROXY"
    else
      echo_failure "Failed to start KMSPROXY"
    fi
}

# returns 0 if KMSPROXY is running, 1 if not running
# side effects: sets KMSPROXY_PID if KMSPROXY is running, or to empty otherwise
kmsproxy_is_running() {
  KMSPROXY_PID=
  if [ -f $KMSPROXY_PID_FILE ]; then
    KMSPROXY_PID=$(cat $KMSPROXY_PID_FILE)
    local is_running=`ps -eo pid | grep "^\s*${KMSPROXY_PID}$"`
    if [ -z "$is_running" ]; then
      # stale PID file
      KMSPROXY_PID=
    fi
  fi
  if [ -z "$KMSPROXY_PID" ]; then
    # check the process list just in case the pid file is stale
    KMSPROXY_PID=$(ps -A ww | grep -v grep | grep java | grep "com.intel.mtwilson.launcher.console.Main jetty-start" | grep "$KMSPROXY_CONFIGURATION" | awk '{ print $1 }')
  fi
  if [ -z "$KMSPROXY_PID" ]; then
    # KMSPROXY is not running
    return 1
  fi
  # KMSPROXY is running and KMSPROXY_PID is set
  return 0
}


kmsproxy_stop() {
  if kmsproxy_is_running; then
    kill -9 $KMSPROXY_PID
    if [ $? ]; then
      echo "Stopped KMSPROXY"
      # truncate pid file instead of erasing,
      # because we may not have permission to create it
      # if we're running as a non-root user
      echo > $KMSPROXY_PID_FILE
    else
      echo "Failed to stop KMSPROXY"
    fi
  fi
}

# removes KMSPROXY home directory (including configuration and data if they are there).
# if you need to keep those, back them up before calling uninstall,
# or if the configuration and data are outside the home directory
# they will not be removed, so you could configure KMSPROXY_CONFIGURATION=/etc/kmsproxy
# and KMSPROXY_REPOSITORY=/var/opt/kmsproxy and then they would not be deleted by this.
kmsproxy_uninstall() {
    rm -f /usr/local/bin/kmsproxy
    if [ -z "$KMSPROXY_HOME" ]; then
      echo_failure "Cannot uninstall because KMSPROXY_HOME is not set"
      return 1
    fi
    if [ "$1" == "--purge" ]; then
      rm -rf $KMSPROXY_HOME $KMSPROXY_CONFIGURATION $KMSPROXY_DATA $KMSPROXY_LOGS
    else
      rm -rf $KMSPROXY_HOME/bin $KMSPROXY_HOME/java $KMSPROXY_HOME/features
    fi
    groupdel $KMSPROXY_USERNAME > /dev/null 2>&1
    userdel $KMSPROXY_USERNAME > /dev/null 2>&1
   
    echo kmsproxy successfully uninstalled
}

print_help() {
    echo "Usage: $0 start|stop|uninstall|version"
    echo "Usage: $0 setup [--force|--noexec] [task1 task2 ...]"
    echo "Available setup tasks:"
    echo $KMSPROXY_SETUP_TASKS | tr ' ' '\n'
}

###################################################################################################

# here we look for specific commands first that we will handle in the
# script, and anything else we send to the java application

case "$1" in
  help)
    print_help
    ;;
  start)
    kmsproxy_start
    ;;
  stop)
    kmsproxy_stop
    ;;
  restart)
    kmsproxy_stop
    kmsproxy_start
    ;;
  status)
    if kmsproxy_is_running; then
      echo "KMSPROXY is running"
      exit 0
    else
      echo "KMSPROXY is not running"
      exit 1
    fi
    ;;
  setup)
    shift
    if [ -n "$1" ]; then
      kmsproxy_setup $*
    else
      kmsproxy_complete_setup
    fi
    ;;
  uninstall)
    shift
    kmsproxy_stop
    kmsproxy_uninstall $*
    ;;
  *)
    if [ -z "$*" ]; then
      print_help
    else
      #echo "args: $*"
      $JAVA_CMD $JAVA_OPTS com.intel.mtwilson.launcher.console.Main $*
    fi
    ;;
esac


exit $?
