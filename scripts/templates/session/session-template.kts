import org.apache.log4j.LogManager
import com.stackhawk.hste.session.ScriptBasedSessionManagementMethodType

val logger = LogManager.getLogger("session-template")

// This function is called after the authentication function to establish a session.
// The sessionWrapper.httpMessage will contain the responseBody, responseHeader and requestingUser which can be used to
// gather data pertaining to the authentication status such as cookies, tokens or data from the responseBody
fun extractWebSession(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
}

// This function is called on each request allow the request to be modified before it is sent to the web application.
fun processMessageToMatchSession(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
}

// Called internally when a new session is required
fun clearWebSessionIdentifiers(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
}

// The required parameter names for your script, your script will throw an error if these are not supplied in the sessionScript.parameters configuration.
fun getRequiredParamsNames(): Array<String> {
    return emptyArray()
}

fun getOptionalParamsNames(): Array<String> {
    return arrayOf("sessionCheckUrl")
}
