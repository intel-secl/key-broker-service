#!/bin/bash

source <(kms --print-env)
# load linux utility
if [ -f "$KMS_HOME/bin/functions.sh" ]; then
  . $KMS_HOME/bin/functions.sh
fi

###################################################################################################

if [ -z "$KMS_PASSWORD" ]; then
  echo_failure "Master password is required; export KMS_PASSWORD"
  return 1
fi

# the subshell allows the java process to have a reasonable current working
# directory without affecting the user's working directory. 
# the last background process pid $! must be stored from the subshell.
(
  cd $KMS_HOME
  $JAVA_CMD $JAVA_OPTS com.intel.mtwilson.launcher.console.Main jetty-start
)
exit $?
