import org.apache.commons.httpclient.URI
import org.apache.log4j.LogManager
import org.parosproxy.paros.network.HttpHeader
import org.parosproxy.paros.network.HttpMessage
import org.parosproxy.paros.network.HttpRequestHeader
import org.zaproxy.zap.authentication.AuthenticationHelper
import org.zaproxy.zap.authentication.GenericAuthenticationCredentials
import org.zaproxy.zap.network.HttpRequestBody


val logger = LogManager.getLogger("Keycloak CC")

val PARAM_ISSUER = "issuer"
val PARAM_GRANT = "grantType"
val CREDS_CLIENTID = "clientId"
val CREDS_SECRET = "clientSecret"

fun authenticate(
    helper: AuthenticationHelper,
    paramsValues: Map<String, String>,
    credentials: GenericAuthenticationCredentials
): HttpMessage {

    logger.info("Keycloak Auth...")

    //build request header
    val requestUri = URI(paramsValues.get(PARAM_ISSUER), false)
    val requestMethod = HttpRequestHeader.POST
    val requestHeader = HttpRequestHeader(requestMethod, requestUri, HttpHeader.HTTP11)
    requestHeader.setHeader("Content-Type", "application/x-www-form-urlencoded")
    requestHeader.setHeader("Accept", "application/json")
    requestHeader.setHeader("Cache-control", "no-cache")

    //build request body
    val requestBody= """
        client_id=${credentials.getParam(CREDS_CLIENTID)}
        &client_secret=${credentials.getParam(CREDS_SECRET)}
        &grant_type=${paramsValues[PARAM_GRANT]}
        """.trimIndent()

    // build final post
    val msg = helper.prepareMessage();
    msg.requestHeader = requestHeader
    msg.requestBody = HttpRequestBody(requestBody)
    requestHeader.contentLength = msg.requestBody.length();

    //send message
    helper.sendAndReceive(msg);
    logger.info("\nMSG ReqHead: " + msg.requestHeader)
    logger.info("\nMSG ReqBody: " + msg.requestBody)
    logger.info("\nMSG ResHead: " + msg.responseHeader)
    logger.info("\nMSG ResBody: " + msg.responseBody)

    return msg;
}


fun getRequiredParamsNames(): Array<String> {
    return arrayOf(PARAM_ISSUER, PARAM_GRANT)
}

fun getOptionalParamsNames(): Array<String> {
    return arrayOf("scope", "audience")
}

fun getCredentialsParamsNames(): Array<String> {
    return arrayOf(CREDS_CLIENTID, CREDS_SECRET)
}

fun getLoggedInIndicator(): String {
    return ".*"
}

fun getLoggedOutIndicator(): String {
    return "this is nonsense"
}
