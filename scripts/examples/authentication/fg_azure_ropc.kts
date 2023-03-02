import org.apache.log4j.LogManager
import org.zaproxy.zap.authentication.GenericAuthenticationCredentials
import org.zaproxy.zap.extension.script.ScriptVars
import org.parosproxy.paros.network.HttpRequestHeader
import org.parosproxy.paros.network.HttpHeader
import org.parosproxy.paros.network.HttpMessage
import org.apache.commons.httpclient.URI
import org.zaproxy.zap.authentication.AuthenticationHelper
import org.zaproxy.zap.network.HttpRequestBody

val logger = LogManager.getLogger("fg_authenticator")

fun authenticate(
    helper: AuthenticationHelper,
    paramsValues: Map<String, String>,
    credentials: GenericAuthenticationCredentials
): HttpMessage {

    logger.info("Fundguard Azure ROPC authenticator")

    // Azure B2C ROPC described here:
    // https://learn.microsoft.com/en-us/azure/active-directory-b2c/add-ropc-policy?tabs=app-reg-ga&pivots=b2c-user-flow
    // construct header
    // construct the target URL from params in form of
    // https://<tenant-name>.b2clogin.com/<tenant-name>.onmicrosoft.com/<policy_name>/oauth2/v2.0/token
    val requestURI = "https://" +
            "${paramsValues['tenant']}.b2clogin.com/" +
            "${paramsValues['tenant']}.onmicrosoft.com/" +
            "${paramsValues['policy']}/oauth2/v2.0/token"
    val requestMethod = HttpRequestHeader.POST
    val requestHeader = HttpRequestHeader(requestMethod, requestURI, HttpHeader.HTTP11)
    requestHeader.addHeader("Host", "${paramsValues['tenant']}.b2clogin.com")
    requestHeader.addHeader("Content-Type", "application/x-www-form-urlencoded")
    logger.info("TARGET_URL: ${requestURI}")

    //construct body in form of
    // username=contosouser.outlook.com.ws&password=Passxword1&grant_type=password
    // &scope=openid+bef22d56-552f-4a5b-b90a-1988a7d634ce+offline_access
    // &client_id=bef22d56-552f-4a5b-b90a-1988a7d634ce&response_type=token+id_token
    val requestBody = "username=${credentials.getParam('username')}" +
                "&password=${credentials.getParam('password')}" +
                "&grant_type=${paramsValues['grant_type']}" +
                "&scope=${paramsValues['scope']}" +
                "&client_id=${paramsValues['client_id']}" +
                "&response_type=token+id_token"

    //construct msg from parts and add body length
    val msg = helper.prepareMessage()
    msg.requestHeader = requestHeader
    msg.requestBody = requestBody
    requestHeader.contentLength = msg.requestBody.length()

    logger.info("auth request: ${msg.requestHeader}\n\n${msg.requestBody}")
    helper.sendAndReceive(msg)
    logger.info("auth response: ${msg.responseHeader}\n\n${msg.responseBody}")
    logger.info("auth complete")
    return msg
}

// The required parameter names for your script, your script will throw an error if these are not supplied in the script.parameters configuration.
fun getRequiredParamsNames(): Array<String> {
    return arrayOf("tenant", "policy", "client_id", "grant_type", "scope")
}

// The required credential parameters, your script will throw an error if these are not supplied in the script.credentials configuration.
fun getCredentialsParamsNames(): Array<String> {
    return arrayOf("username", "password")
}

fun getOptionalParamsNames(): Array<String> {
    return arrayOf()
}
