import org.apache.commons.httpclient.URI
import org.apache.log4j.LogManager
import org.parosproxy.paros.network.HttpHeader
import org.parosproxy.paros.network.HttpMessage
import org.parosproxy.paros.network.HttpRequestHeader
import com.stackhawk.hste.authentication.AuthenticationHelper
import com.stackhawk.hste.authentication.GenericAuthenticationCredentials
import com.stackhawk.hste.extension.script.ScriptVars

val logger = LogManager.getLogger("token-for-cookie")

// This function is called before a scan is started and when the loggedOutIndicator is matched indicating re-authentication is needed.
fun authenticate(
    helper: AuthenticationHelper,
    paramsValues: Map<String, String>,
    credentials: GenericAuthenticationCredentials
): HttpMessage {

    // save the auth token name for use in session management
    ScriptVars.setGlobalVar("authTokenName", paramsValues["authTokenName"])

    // make a request to the authUrl using the supplied external token as a header
    val requestUri = URI(paramsValues["authUrl"], false)
    val requestMethod = HttpRequestHeader.GET
    val requestHeader = HttpRequestHeader(requestMethod, requestUri, HttpHeader.HTTP11)
    requestHeader.addHeader(paramsValues["authTokenName"], credentials.getParam("authTokenValue"))
    val msg = helper.prepareMessage()
    msg.requestHeader = requestHeader
    logger.info("auth request: $${msg.requestHeader}")
    helper.sendAndReceive(msg)
    logger.info("auth complete")
    // return the msg containing the request and response from the authentication request for session processing
    return msg
}

// The required parameter names for your script, your script will throw an error if these are not supplied in the script.parameters configuration.
fun getRequiredParamsNames(): Array<String> {
    return arrayOf("authUrl", "authTokenName")
}

// The required credential parameters, your script will throw an error if these are not supplied in the script.credentials configuration.
fun getCredentialsParamsNames(): Array<String> {
    return arrayOf("authTokenValue")
}

fun getOptionalParamsNames(): Array<String> {
    return emptyArray()
}
