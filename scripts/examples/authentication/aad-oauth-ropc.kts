import org.apache.commons.httpclient.URI
import org.apache.log4j.LogManager
import org.parosproxy.paros.network.HttpHeader
import org.parosproxy.paros.network.HttpMessage
import org.parosproxy.paros.network.HttpRequestHeader
import org.zaproxy.zap.authentication.AuthenticationHelper
import org.zaproxy.zap.authentication.GenericAuthenticationCredentials
import org.zaproxy.zap.network.HttpRequestBody

val logger = LogManager.getLogger("AAD_ROPC_Logger")

val PARAM_BASE_URL = "baseUrl"
val PARAM_TENANT = "tenant"
val PARAM_SCOPE = "scope"
val PARAM_GRANT = "grantType"
val CREDS_ID = "clientId"
val CREDS_USER = "username"
val CREDS_PASS = "password"

// This function is called before a scan is started and when the loggedOutIndicator is matched indicating re-authentication is needed.
fun authenticate(
    helper: AuthenticationHelper,
    paramsValues: Map<String, String>,
    credentials: GenericAuthenticationCredentials
): HttpMessage {

    logger.info("AAD OAuth ROPC Example -- Customize")

    val targetURL = "${paramsValues[PARAM_BASE_URL]}/${PARAM_TENANT}/oauth2/v2.0/token"
    logger.info("TARGET_URL: $targetURL\n")
    val msg = helper.prepareMessage()
    msg.requestHeader = HttpRequestHeader(
        HttpRequestHeader.POST, URI(targetURL, true),
        HttpHeader.HTTP11
    )
    msg.requestHeader.addHeader("Content-Type", "application/x-www-form-urlencoded")

    val body = """
        client_id=${credentials.getParam(CREDS_ID)}
        &scope=${paramsValues[PARAM_SCOPE]}
        &username=${credentials.getParam(CREDS_USER)}
        &password=${credentials.getParam(CREDS_PASS)}
        &grant_type=${paramsValues[PARAM_GRANT]}
    """.trimIndent()

    msg.requestBody = HttpRequestBody(body)

    msg.requestHeader.contentLength = msg.requestBody.length()

    helper.sendAndReceive(msg)
    logger.info("MSG SENT:\n${msg.requestHeader}\n\n${msg.requestBody}")
    logger.info("MSG RECV:\n${msg.responseHeader}\n\n${msg.responseBody}")

    return msg
}

// The required parameter names for your script, your script will throw an error if these are not supplied in the script.parameters configuration.
fun getRequiredParamsNames(): Array<String> {
    return arrayOf(PARAM_BASE_URL, PARAM_TENANT, PARAM_SCOPE, PARAM_GRANT)
}

// The required credential parameters, your script will throw an error if these are not supplied in the script.credentials configuration.
fun getCredentialsParamsNames(): Array<String> {
    return arrayOf(CREDS_ID, CREDS_USER, CREDS_PASS)
}

fun getOptionalParamsNames(): Array<String> {
    return arrayOf()
}

fun getLoggedInIndicator(): String {
    return ".*"
}

fun getLoggedOutIndicator(): String {
    return "banana-fofana" // might fail for Juice Shop
}