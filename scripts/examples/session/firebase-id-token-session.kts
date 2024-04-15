import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import org.apache.commons.httpclient.Cookie
import org.apache.log4j.LogManager
import org.zaproxy.zap.session.ScriptBasedSessionManagementMethodType

val logger = LogManager.getLogger("firebase-id-token")
val mapper = ObjectMapper()

// This function is called after the authentication function to establish a session.
// The sessionWrapper.httpMessage will contain the responseBody, responseHeader and requestingUser which can be used to
// gather data pertaining to the authentication status such as cookies, tokens or data from the responseBody
fun extractWebSession(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
    val tokenName = sessionWrapper.getParam("tokenName")
    val cookieName = sessionWrapper.getParam("cookieName")
    val domain = sessionWrapper.getParam("domain")
    val jsonObject = mapper.readValue(sessionWrapper.httpMessage.responseBody.bytes, ObjectNode::class.java)
    val cookieValue = jsonObject.get(tokenName).asText()
    val cookie = Cookie(domain, cookieName, cookieValue)

    logger.debug("Adding session cookie ${cookie.name} wtih value ${cookie.value}" )
    sessionWrapper.session.httpState.addCookie(cookie)
}

// This function is called on each request allow the reuqest to be modified before it is sent to the web application.
fun processMessageToMatchSession(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {

}

// Called internally when a new session is required
fun clearWebSessionIdentifiers(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
}

// The required parameter names for your script, your script will throw an error if these are not supplied in the sessionScript.parameters configuration.
fun getRequiredParamsNames(): Array<String> {
    return arrayOf("cookieName", "domain")
}

fun getOptionalParamsNames(): Array<String> {
    return emptyArray()
}
