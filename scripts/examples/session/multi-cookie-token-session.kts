import org.apache.log4j.LogManager
import org.apache.log4j.Logger
import com.stackhawk.hste.session.ScriptBasedSessionManagementMethodType
import com.stackhawk.hste.extension.script.ScriptVars

val logger: Logger = LogManager.getLogger("multi-cookie-token-session")

// This function is called after the authentication function to establish a session.
// The sessionWrapper.httpMessage will contain the responseBody, responseHeader and requestingUser which can be used to
// gather data pertaining to the authentication status such as cookies, tokens or data from the responseBody
fun extractWebSession(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {

    var cookieIterator = 0
    logger.info("Setting session cookies")
    while (ScriptVars.getGlobalVars().containsKey("cookieName$cookieIterator")) {
        // Change domain to match the domain of your site
        val domain = "localhost"
        val httpCookie = org.apache.commons.httpclient.Cookie(domain,
            ScriptVars.getGlobalVar("cookieName$cookieIterator"),
            ScriptVars.getGlobalVar("cookieValue$cookieIterator"))
        logger.info("Adding session cookie ${httpCookie.name} wtih value ${httpCookie.value}" )
        sessionWrapper.session.httpState.addCookie(httpCookie)
        cookieIterator++
    }

}


// This function is called on each request allow the request to be modified before it is sent to the web application.
fun processMessageToMatchSession(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
    var tokenIterator = 0
    logger.info("Setting token headers")
    while (ScriptVars.getGlobalVars().containsKey("tokenName$tokenIterator")) {
        logger.info("Adding session token ${ScriptVars.getGlobalVar("tokenName$tokenIterator")} with value ${  ScriptVars.getGlobalVar("tokenValue$tokenIterator")}" )
        sessionWrapper.httpMessage.requestHeader.addHeader(
            ScriptVars.getGlobalVar("tokenName$tokenIterator"),
            ScriptVars.getGlobalVar("tokenValue$tokenIterator")
        )
        tokenIterator++
    }
}

// Called internally when a new session is required
fun clearWebSessionIdentifiers(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
}

// The required parameter names for your script, your script will throw an error if these are not supplied in the sessionScript.parameters configuration.
fun getRequiredParamsNames(): Array<String> {
    return arrayOf()
}

fun getOptionalParamsNames(): Array<String> {
    return arrayOf()
}