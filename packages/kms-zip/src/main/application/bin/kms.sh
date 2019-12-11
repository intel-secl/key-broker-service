#!/bin/bash

# chkconfig: 2345 80 30
# description: Intel Key Management Service

### BEGIN INIT INFO
# Provides:          kms
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Should-Start:      $portmap
# Should-Stop:       $portmap
# X-Start-Before:    nis
# X-Stop-After:      nis
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# X-Interactive:     true
# Short-Description: kms
# Description:       Main script to run kms commands
### END INIT INFO
DESC="KMS"
NAME=kms

# the home directory must be defined before we load any environment or
# configuration files; it is explicitly passed through the sudo command
# below
export KMS_HOME=${KMS_HOME:-/opt/kms}
export KMS_BIN=${KMS_BIN:-$KMS_HOME/bin}

print_env() {
    # the cd into KMS_HOME prevents this message from appearing when this
    # command is run as the `kms` user from a private directory e.g. /root:
    # find: Failed to restore initial working directory: /root: Permission denied
    (
        cd $KMS_HOME
        env -i bash --norc $KMS_HOME/script/kms-env.sh $2
    )
}

if [ -n "$1" ] && [ "$1" = "--print-env" ]; then
    print_env
    exit $?
fi

source <(print_env)


###################################################################################################

# if non-root execution is specified, and we are currently root, start over; the KMS_SUDO variable limits this to one attempt
# we make an exception for the uninstall command, which may require root access to delete users and certain directories
if [ -n "$KMS_USERNAME" ] && [ "$KMS_USERNAME" != "root" ] && [ $(whoami) == "root" ] && [ -z "$KMS_SUDO" ] && [ "$1" != "uninstall" ]; then
#7087 fix
#if [ -n "$KMS_USERNAME" ] && [ "$KMS_USERNAME" != "root" ] && [ $(whoami) == "root" ] && [ -z "$KMS_SUDO" ] && [ "$1" != "stop" ]  && [ "$1" != "uninstall" ] && [ "$1" != "init" ] && [ "$1" != "config" ] && [ "$1" != "setup" ] && [ "$1" != "password" ]; then
  export KMS_SUDO=true
  sudo -u $KMS_USERNAME -H -E $KMS_BIN/kms.sh $*
  exit $?
fi

# after sudo we need to reload the environment settings
if [ -n "$KMS_SUDO" ] && [ "$KMS_SUDO" = "true" ]; then
    source <(print_env)
fi

###################################################################################################


# load linux utility
if [ -f "$KMS_HOME/bin/functions.sh" ]; then
  . $KMS_HOME/bin/functions.sh
fi


###################################################################################################

# all other variables with defaults
KMS_SETUP_FIRST_TASKS=${KMS_SETUP_FIRST_TASKS:-""}
KMS_SETUP_TASKS=${KMS_SETUP_TASKS:-"password-vault jetty-tls-keystore shiro-ssl-port notary-key envelope-key storage-key saml-certificates tpm-identity-certificates"}
KMS_SETUP_AUTHORIZE_TASKS=${KMS_SETUP_AUTHORIZE_TASKS:-"saml-certificates tpm-identity-certificates"}

# the standard PID file location /var/run is typically owned by root;
# if we are running as non-root and the standard location isn't writable 
# then we need a different place;  assume /var/run and logs dir already exist
KMS_PID_FILE=${KMS_PID_FILE:-/var/run/kms.pid}
touch $KMS_PID_FILE >/dev/null 2>&1
if [ $? == 1 ]; then KMS_PID_FILE=$KMS_LOGS/kms.pid; fi

###################################################################################################

# run a kms command
kms_run() {
  local args="$*"
  $JAVA_CMD $JAVA_OPTS com.intel.mtwilson.launcher.console.Main $args
  return $?
}

# run default set of setup tasks and check if admin user needs to be created
kms_complete_setup() {
  # run all setup tasks, don't use the force option to avoid clobbering existing
  # useful configuration files
  ( kms_setup update-extensions-cache-file )
  #kms_setup $KMS_SETUP_FIRST_TASKS
  ( kms_setup $KMS_SETUP_TASKS )
  # if this is a Kepler Lake install, the `kpl` will be available:
  # if which kpl >/dev/null; then
  #  source <(kpl --print-env)
  #fi
  # TODO: need a way to identify a MTWILSON install, and only run these MTWILSON tasks if it's a
  #       MTWILSON install, instead of checking if it's NOT a KPL and NOT a DHSM install
  if [ -z "$KPL_HOME" ]; then
    ( kms_setup $KMS_SETUP_AUTHORIZE_TASKS )
  fi
}

# arguments are optional, if provided they are the names of the tasks to run, in order
kms_setup() {
  local args="$*"
  if [[ "$*" =~ "update-extensions-cache-file" ]]; then
    # when scanning for extensions, we don't want to load the extensions cache
    # and get errors about previously registered extensions that are no longer
    # in the class path;  for this reason this setup task should be executed
    # separately from other setup tasks.
    JAVA_OPTS="$JAVA_OPTS -DUseExtensionCacheLoader=false"
  fi
  kms_run setup $args
  return $?
}

kms_start_check() {
  if [ -z "$KMS_PASSWORD" ]; then
    echo_failure "Master password is required; export KMS_PASSWORD"
    return 1
  fi

  # check if we're already running - don't start a second instance
  if kms_is_running; then
      echo "KMS is running"
      return 0
  fi

  kms_start 2>&1 >/dev/null
  for (( i = 1; i <= 12; i++ )); do
    sleep 1
    if kms_is_running; then
      break;
    elif (( $i % 3 == 0 )); then
      kms_start 2>&1 >/dev/null
    fi
  done
  if kms_is_running; then
    echo_success "Started KMS"
  else
    echo_failure "Failed to start KMS"
  fi
}

kms_start() {
    # the subshell allows the java process to have a reasonable current working
    # directory without affecting the user's working directory. 
    # the last background process pid $! must be stored from the subshell.
    (
      cd $KMS_HOME
      "$JAVA_CMD" $JAVA_OPTS com.intel.mtwilson.launcher.console.Main jetty-start >>$KMS_HTTP_LOG_FILE 2>&1 &
      echo $! > $KMS_PID_FILE
    )
}

# returns 0 if KMS is running, 1 if not running
# side effects: sets KMS_PID if KMS is running, or to empty otherwise
kms_is_running() {
  KMS_PID=
  if [ -f $KMS_PID_FILE ]; then
    KMS_PID=$(cat $KMS_PID_FILE)
    local is_running=`ps -A -o pid | grep "^\s*${KMS_PID}$"`
    if [ -z "$is_running" ]; then
      # stale PID file
      KMS_PID=
    fi
  fi
  if [ -z "$KMS_PID" ]; then
    # check the process list just in case the pid file is stale
    KMS_PID=$(ps -A ww | grep -v grep | grep java | grep "com.intel.mtwilson.launcher.console.Main jetty-start" | grep "$KMS_CONFIGURATION" | awk '{ print $1 }')
  fi
  if [ -z "$KMS_PID" ]; then
    # KMS is not running
    return 1
  fi
  # KMS is running and KMS_PID is set
  return 0
}


kms_stop() {
  if kms_is_running; then
    kill -9 $KMS_PID
    if [ $? ]; then
      echo "Stopped KMS"
      # truncate pid file instead of erasing,
      # because we may not have permission to create it
      # if we're running as a non-root user
      echo > $KMS_PID_FILE
    else
      echo "Failed to stop KMS"
    fi
  fi
}

# removes KMS home directory (including configuration and data if they are there).
# if you need to keep those, back them up before calling uninstall,
# or if the configuration and data are outside the home directory
# they will not be removed, so you could configure KMS_CONFIGURATION=/etc/kms
# and KMS_REPOSITORY=/var/opt/kms and then they would not be deleted by this.
kms_uninstall() {
    rm -f /usr/local/bin/kms
    if [ -z "$KMS_HOME" ]; then
      echo_failure "Cannot uninstall because KMS_HOME is not set"
      return 1
    fi
    remove_startup_script kms
    if [ "$1" == "--purge" ]; then
      rm -rf $KMS_HOME $KMS_CONFIGURATION $KMS_DATA $KMS_LOGS
    else
      rm -rf $KMS_HOME/bin $KMS_HOME/java $KMS_HOME/features
    fi
    rm -rf /etc/logrotate.d/kms
    groupdel $KMS_USERNAME > /dev/null 2>&1
    userdel $KMS_USERNAME > /dev/null 2>&1
    echo "KMS successfully uninstalled"
}

print_help() {
    echo "Usage: $0 start|stop|status|restart|uninstall|version"
    echo "Usage: $0 setup [--force|--noexec] [task1 task2 ...]"
    echo "Available setup tasks:"
    echo $KMS_SETUP_TASKS | tr ' ' '\n'
}

###################################################################################################

# here we look for specific commands first that we will handle in the
# script, and anything else we send to the java application

case "$1" in
  help)
    print_help
    ;;
  start)
    kms_start_check
    ;;
  stop)
    kms_stop
    ;;
  restart)
    kms_stop
    kms_start_check
    ;;
  status)
    if kms_is_running; then
      echo "KMS is running"
      exit 0
    else
      echo "KMS is not running"
      exit 1
    fi
    ;;
  init)
    bash $KMS_HOME/script/kms-init.sh
    exit 0
    ;;
  setup)
    shift
    if [ -n "$1" ]; then
      kms_setup $*
    else
      kms_complete_setup
    fi
    ;;
  uninstall)
    shift
    kms_stop
    kms_uninstall $*
    ;;
  keytool)
    shift
    $JAVA_HOME/jre/bin/keytool $*
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
