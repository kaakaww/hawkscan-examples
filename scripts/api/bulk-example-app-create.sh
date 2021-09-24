#!/usr/bin/env bash
#   StackHawk Bulk Application Creation Script
#   This script will create multiple applications and environments in the specified StackHawk organization
#   Usage: copy and modify this script to suit your needs. Change the appNames and envNames to match your needs
#   define a $SH_API_KEY with a API Key from StackHawk https://app.stackhawk.com/settings/apikeys
#   specify the $SH_ORG_ID with the organizationId that will receive the applications
#   see https://docs.stackhawk.com/apidocs.html for more details
APP_NAMES=("\U0001F34B-LEMON" "\U0001F352-CHERRY" "\U0001F34F-APPLE" "\U0001FAD0-BERRY" "\U0001F965-COCONUT")
ENV_NAMES=("dev" "test" "prod")

function createApp {
    token="$1"
    orgId="$2"
    appName=$(printf "$3")
    envName="$4"

    appId=$(curl --request POST \
     --url https://api.stackhawk.com/api/v1/org/$orgId/app \
     --header 'Accept: application/json' \
     --header "Authorization: Bearer $token" \
     --header 'Content-Type: application/json' \
     --data "
{
     \"dataType\": \"NONE\",
     \"riskLevel\": \"MEDIUM\",
     \"env\": \"$envName\",
     \"name\": \"$appName\",
     \"organizationId\": \"$orgId\"
}
" \
    | jq -r .applicationId)

    echo "$appId"
}

function createAppEnv {
    token="$1"
    orgId="$2"
    appId="$3"
    envName="$4"

    envId=$(curl --request POST \
     --url https://api.stackhawk.com/api/v1/app/$appId/env \
     --header 'Accept: application/json' \
     --header "Authorization: Bearer $token" \
     --header 'Content-Type: application/json' \
     --data "
{
     \"env\": \"$envName\",
     \"applicationId\": \"$appId\"
}
" \
    | jq -r .envId)

    echo "$envId"
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

echo "This will generate ${#APP_NAMES[@]} applications with ${#ENV_NAMES[@]} environments each in the $SH_ORG_ID organization"
echo "press any key to continue..."
read -r

token=$(curl --request GET \
    --url https://api.stackhawk.com/api/v1/auth/login \
    --header 'Accept: application/json' \
    --header "X-ApiKey: $SH_API_KEY" \
    | jq -r '.token')
echo "$token"

for a in "${!APP_NAMES[@]}"; do
    appName=${APP_NAMES[$a]}
    appId=""
    for e in "${!ENV_NAMES[@]}"; do
        envName=${ENV_NAMES[$e]}
        if [[ $envName == 'dev' ]]; then
            appId=$(createApp $token $SH_ORG_ID $appName $envName)
            echo -e "created app $appId - $appName $envName"
        else
            envId=$(createAppEnv $token $SH_ORG_ID $appId $envName)
            echo -e "created env $envId - $appName $envName"
        fi
    done
done
