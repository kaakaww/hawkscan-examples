import org.apache.commons.httpclient.URI
import org.apache.log4j.LogManager
import org.parosproxy.paros.network.HttpHeader
import org.parosproxy.paros.network.HttpMessage
import org.parosproxy.paros.network.HttpRequestHeader
import org.zaproxy.zap.authentication.AuthenticationHelper
import org.zaproxy.zap.authentication.GenericAuthenticationCredentials
import org.zaproxy.zap.network.HttpRequestBody

val logger = LogManager.getLogger("Keycloak-ROPC-Auth-Script")

// This function is called before a scan is started and when the loggedOutIndicator is matched indicating re-authentication is needed.
fun authenticate(
    helper: AuthenticationHelper,
    paramsValues: Map<String, String>,
    credentials: GenericAuthenticationCredentials
): HttpMessage {
    logger.info("Keycloak Resource Owner Password Authentication: Go!")

    val baseUrl = paramsValues["baseUrl"]
    val realm = paramsValues["realm"]
    val clientId = credentials.getParam("clientId")
    val username = credentials.getParam("username")
    val password = credentials.getParam("password")
    val grantType = "password"
    val openidConfigEndpoint = "${baseUrl}/realms/${realm}/.well-known/openid-configuration"
    val tokenEndpoint = "${baseUrl}/realms/${realm}/protocol/openid-connect/token"
    val authRequestBody = "client_id=${clientId}&username=${username}&password=${password}&grant_type=${grantType}"

    logger.info("OpenID Configuration Endpoint: $openidConfigEndpoint")
    logger.info("Token Endpoint: $tokenEndpoint")

    val msg = helper.prepareMessage()
    msg.requestHeader = HttpRequestHeader(
        HttpRequestHeader.POST,
        URI(tokenEndpoint, false),
        HttpHeader.HTTP11
    )
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
     *      baseUrl:    The base URL for the Keycloak server, e.g. http://localhost:8180
     *      realm:      The Keycloak authentication realm
     */
    return arrayOf("baseUrl", "realm")
}

// The required credential parameters, your script will throw an error if these are not supplied in the script.credentials configuration.
// Add these credential parameters to your HawkScan configuration file under app.authentication.script.credentials.
fun getCredentialsParamsNames(): Array<String> {
    /**
     * @return
     *      clientId:   Your Keycloak client ID
     *      username:   Your Keycloak username
     *      password:   Your Keycloak password
     */
    return arrayOf("clientId", "username", "password")
}

// Add these optional parameters to your HawkScan configuration file under app.authentication.script.parameters.
fun getOptionalParamsNames(): Array<String> {
    return arrayOf()
}
