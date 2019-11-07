#!/bin/bash
#Steps:
#Get token from AAS
#to customize, export the correct values before running the script

echo "Setting up KMS Related roles and user in AAS Database"
unset https_proxy
unset http_proxy

CURL_OPTS="--cacert /opt/kms/configuration/cms-ca.cert"

#Get the value of AAS IP address and port. Default vlue is also provided.
export aas_hostname=$AAS_API_URL
export cms_hostanme=$CMS_BASE_URL

mkdir -p /tmp/setup/kms
tmpdir=$(mktemp -d -p /tmp/setup/kms)

#Get CMS CA Certificate
curl --insecure -X GET -H "Accept: application/x-pem-file" -w "%{http_code}" {$cms_hostanme}ca-certificates -o /opt/kms/configuration/cms-ca.cert > $tmpdir/cms-ca-response.status 2>$tmpdir/cms-ca-debug.log

export kms_username=$USERNAME
export kms_password=$PASSWORD

cat > $tmpdir/user.json << EOF
{
		"username":"$kms_username",
		"password":"$kms_password"
}
EOF

#Get the JWT Token

Bearer_token=$AAS_ADMIN_TOKEN
if [ -z "$Bearer_token" ]; then
	echo "unable to get aasAdmin token from kms.env. It is not present."
	exit 1
fi

#Create kmsUser also get user id
create_kms_user() {
curl $CURL_OPTS -X POST -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/user.json -o $tmpdir/createkmsuser-response.json -w "%{http_code}" $aas_hostname/users > $tmpdir/createkmsuser-response.status 2>$tmpdir/createkmsuser-debug.log

local actual_status=$(cat $tmpdir/createkmsuser-response.status)
if [ $actual_status -eq 401 ]; then
	echo "aasToken is expired/not correct. Please check"
	exit 1
fi
if [ $actual_status -ne 201 ]; then
	local response_mesage=$(cat $tmpdir/createkmsuser-response.json)
	if [ "$response_mesage" != "same user exists" ]; then
		return 1 
	fi
	#If the user exists script should get its id and save it in KMS_USER_ID
	jq < $tmpdir/user.json 2> /dev/null
	user_name=$(jq -r '.username' < $tmpdir/user.json)
	if [ -n "$user_name" ]; then
		echo "got user name: $user_name"
	fi

	curl $CURL_OPTS -X GET -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}" -o $tmpdir/get_kmsUser-response.json -w "%{http_code}" $aas_hostname/users\?name=$user_name > $tmpdir/get_kmsUser-response.status 2>$tmpdir/get_kmsUser-debug.log

	jq < $tmpdir/get_kmsUser-response.json 2> /dev/null
	user_id=$(jq -r '.[0].user_id' < $tmpdir/get_kmsUser-response.json)
	if [ -n "$user_id" ]; then
		echo "got user id: $user_id"
		KMS_USER_ID=$user_id;
	fi
	return
fi

if [ -s $tmpdir/createkmsuser-response.json ]; then
	jq < $tmpdir/createkmsuser-response.json
	user_id=$(jq -r '.user_id' < $tmpdir/createkmsuser-response.json)
	if [ -n "$user_id" ]; then
		echo "Created user id: $user_id"
		KMS_USER_ID=$user_id;
	fi
fi
}

#Create roles for which serice=KMS
create_user_roles() {
cat > $tmpdir/roles.json << EOF
{
	"service": "$1",
	"name": "$2",
	"context": "$3"
}
EOF

curl $CURL_OPTS -X POST -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/roles.json -o $tmpdir/role-response-$1-$2.json -w "%{http_code}" $aas_hostname/roles > $tmpdir/role-response-$1-$2.status 2>$tmpdir/role-debug-$1-$2.log

local actual_status=$(cat $tmpdir/role-response-$1-$2.status)
if [ $actual_status -ne 201 ]; then
	local response_mesage=$(cat $tmpdir/role-response-$1-$2.json)
	if [ "$response_mesage" == "same role exists" ]; then
		echo "0"
	else
		echo "1"
	fi
fi
echo "0"
}

#This step is needed to map existing role i.e. userRole as getRoles is not yet implemented.
#KMS Roles are to be mapped certAprrover and roleManager. Since role manager are not implemented hence usermanager, rolemanager, usetRoleManager
getRoles() {
if [ "$#" -eq 3 ]; then
	curl $CURL_OPTS -X GET -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}" -o $tmpdir/get_role-response.json -w "%{http_code}" $aas_hostname/roles\?service\=$1\&name\=$2\&contextContains=$3> $tmpdir/get_role-response.status 2>$tmpdir/get_role-debug.log
else
	curl $CURL_OPTS -X GET -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}" -o $tmpdir/get_role-response.json -w "%{http_code}" $aas_hostname/roles\?service\=$1\&name\=$2> $tmpdir/get_role-response.status 2>$tmpdir/get_role-debug.log
fi

local actual_status=$(cat $tmpdir/get_role-response.status)

if [ $actual_status -eq 401 ]; then
	echo "aasToken is expired/not correct. Please check."
	exit 1
fi

if [ $actual_status -ne 200 ]; then
	return 1
fi

if [ -s $tmpdir/get_role-response.json ]; then
        	jq < $tmpdir/get_role-response.json 2> /dev/null
        	role_id=$(jq -r '.[].role_id' < $tmpdir/get_role-response.json)
fi
echo $role_id
}

get_KMS_Roles() {
	#local aas_role_id=$( "AAS" "getroles" "CN=KMS TLS Certificate; SAN=127.0.0.1,localhost;CERTTYPE=TLS" )
	local aas_role_manager_id=$( getRoles "AAS" "RoleManager" "KMS")
	local aas_user_manager_id=$( getRoles "AAS" "UserManager" )
	local aas_user_role_manager_id=$(getRoles "AAS" "UserRoleManager") #so that KMS can map roles.
	local cms_role_id=$(getRoles "CMS" "CertApprover" "KMS%20TLS%20Certificate")

	#check if any role is missing exit
	if [[ -z $aas_role_manager_id || -z $aas_user_manager_id
	|| -z $aas_user_role_manager_id || -z $cms_role_id ]]; then
		echo "role doesn't exist"
		exit 1
		#return 1;
	fi
	#ROLE_ID_TO_MAP=`echo "\"$cms_role_id""\",\""$aas_role_id\",\""$aas_role_manager_id\",\""$aas_user_manager_id\",\""$aas_user_role_manager_id\""`
	ROLE_ID_TO_MAP=`echo "\"$cms_role_id""\",\""$aas_role_manager_id\",\""$aas_user_manager_id\",\""$aas_user_role_manager_id\"`
	echo $ROLE_ID_TO_MAP
}

#As per the new requirement only KMS related roles will be created at installation time. Rest all will be done out of band. 
create_roles() {
	if [[ "$(create_user_roles "KMS" "KeyCRUD" "Permissions=*:*:*")" != "0" ]]; then
		return "1";
	fi
}

#Map kmsUser to Roles
mapUser_to_role() {
cat >$tmpdir/mapRoles.json <<EOF
{
	"role_ids": [$ROLE_ID_TO_MAP]
}
EOF

curl $CURL_OPTS -X POST -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/mapRoles.json -o $tmpdir/mapRoles-response.json -w "%{http_code}" $aas_hostname/users/$user_id/roles > $tmpdir/mapRoles-response.status 2>$tmpdir/mapRoles-debug.log
local actual_status=$(cat $tmpdir/mapRoles-response.status)

if [ $actual_status -eq 401 ]; then
	echo "aasToken is expired/not correct. Please check."
	exit 1
fi
if [ $actual_status -ne 201 ]; then
	return 1 
fi
}

KMS_SETUP_API="create_kms_user get_KMS_Roles mapUser_to_role"

status=
for api in $KMS_SETUP_API
do
	echo $api
	eval $api
    	status=$?
	echo $status
    if [ $status -ne 0 ]; then
        echo "AAS details creation stopped.: $api"
        break;
    fi
done

if [ $status -eq 0 ]; then
	create_roles
	retval=$?
	if [ "$retval" != 0 ]; then
		echo "kms specific roles not created/Already Present. Try to create them manually."
	fi
fi

# cleanup
#rm -rf $tmpdir
