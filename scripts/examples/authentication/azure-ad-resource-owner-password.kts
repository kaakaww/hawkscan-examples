import org.apache.commons.httpclient.URI
import org.apache.log4j.LogManager
import org.parosproxy.paros.network.HttpHeader
import org.parosproxy.paros.network.HttpMessage
import org.parosproxy.paros.network.HttpRequestHeader
import org.zaproxy.zap.authentication.AuthenticationHelper
import org.zaproxy.zap.authentication.GenericAuthenticationCredentials
import org.zaproxy.zap.network.HttpRequestBody

val logger = LogManager.getLogger("AAD-ROPC-Auth-Script")

// This function is called before a scan is started and when the loggedOutIndicator is matched indicating re-authentication is needed.
fun authenticate(
    helper: AuthenticationHelper,
    paramsValues: Map<String, String>,
    credentials: GenericAuthenticationCredentials
): HttpMessage {
    logger.info("AAD Resource Owner Password Authentication: Go!")

    val baseUrl = "https://login.microsoftonline.com"
    val tenant = paramsValues["tenant"]
    val scopeOption = if (paramsValues.containsKey("scope")) "&scope=" + paramsValues["scope"] else ""
    val clientId = credentials.getParam("clientId")
    val username = credentials.getParam("username")
    val password = credentials.getParam("password")
    val grantType = "password"
    val openidConfigEndpoint = "${baseUrl}/${tenant}/v2.0/.well-known/openid-configuration"
    val tokenEndpoint = "${baseUrl}/${tenant}/oauth2/v2.0/token"
    val authRequestBody = "client_id=${clientId}&username=${username}&password=${password}&grant_type=${grantType}${scopeOption}"

    logger.info("OpenID Configuration Endpoint: $openidConfigEndpoint")
    logger.info("Token Endpoint: $tokenEndpoint")

    val msg = helper.prepareMessage()
    msg.requestHeader = HttpRequestHeader(
        HttpRequestHeader.POST,
        URI(tokenEndpoint, false),
        HttpHeader.HTTP11
    )
    msg.requestHeader.setHeader("Content-Type", "application/x-www-form-urlencoded")
    msg.requestHeader.setHeader("Accept", "application/json")
    msg.requestHeader.setHeader("Cache-control", "no-cache")
    msg.requestBody = HttpRequestBody(authRequestBody)
    msg.requestHeader.contentLength = msg.requestBody.length()

    helper.sendAndReceive(msg)
    logger.info("Auth Request:\n=== REQUEST HEADERS ===\n${msg.requestHeader}\n=== REQUEST BODY ===\n${msg.requestBody}\n")
    logger.info("Auth Response:\n=== RESPONSE HEADERS ===\n${msg.responseHeader}\n=== RESPONSE BODY ===\n${msg.responseBody}\n")

    return msg
}

// The required parameter names for your script, your script will throw an error if these are not supplied in the script.parameters configuration.
// Add these parameters to your HawkScan configuration file under app.authentication.script.parameters.
fun getRequiredParamsNames(): Array<String> {
    /**
     * @return
     *      tenant: The directory tenant that you want to log the user into. The tenant can be in GUID or friendly name format
     */
    return arrayOf("tenant")
}

// The required credential parameters, your script will throw an error if these are not supplied in the script.credentials configuration.
// Add these credential parameters to your HawkScan configuration file under app.authentication.script.credentials.
fun getCredentialsParamsNames(): Array<String> {
    /**
     * @return
     *      clientId:   The Application (client) ID that the Azure portal - App registrations page assigned to your app
     *      username:   Your AAD username
     *      password:   Your AAD password
     */
    return arrayOf("clientId", "username", "password")
}

// Add these optional parameters to your HawkScan configuration file under app.authentication.script.parameters.
fun getOptionalParamsNames(): Array<String> {
    /**
     * @return
     *      scope:  A space-separated list of scopes, or permissions, that the app requires
     */
    return arrayOf("scope")
}
