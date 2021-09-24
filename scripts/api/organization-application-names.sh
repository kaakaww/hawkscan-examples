#!/usr/bin/env bash
#   StackHawk Organization application Ids
#   This script will report the application names (or ids) that belong to the orgnization
#   define a $SH_API_KEY with a API Key from StackHawk https://app.stackhawk.com/settings/apikeys
#   specify the $SH_ORG_ID with the organizationId that will receive the applications
#   see https://docs.stackhawk.com/apidocs.html for more details

function listOrgAppNames {
    token="$1"
    orgId="$2"
    appIds=$(curl --request GET \
     --url "https://api.stackhawk.com/api/v1/app/$orgId/list?ignoreEnvs=true&pageSize=50" \
     --header 'Accept: application/json' \
     --header "Authorization: Bearer $token" \
     | jq -r '.applications[] | .name')
    echo "$appIds"
}

function listOrgAppIds {
    token="$1"
    orgId="$2"
    appIds=$(curl --request GET \
     --url "https://api.stackhawk.com/api/v1/app/$orgId/list?ignoreEnvs=true&pageSize=50" \
     --header 'Accept: application/json' \
     --header "Authorization: Bearer $token" \
     | jq -r '.applications[] | .applicationId')
    echo "$appIds"
}

if [ -z "$SH_API_KEY" ]
then
echo "\$SH_API_KEY is not yet set"
exit 1
fi

if [ -z "$SH_ORG_ID" ]
then
echo "\$SH_ORG_ID is not yet set"
exit 1
fi

echo "This will report the applicationIds that belong to the $SH_ORG_ID organization"
echo "press any key to continue..."
read -r

token=$(curl --request GET \
    --url https://api.stackhawk.com/api/v1/auth/login \
    --header 'Accept: application/json' \
    --header "X-ApiKey: $SH_API_KEY" \
    | jq -r '.token')
echo "$token"

appNames=$( listOrgAppNames $token $SH_ORG_ID )

for appName in $appNames
do
echo $appName
done

