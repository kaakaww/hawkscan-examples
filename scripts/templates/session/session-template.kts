import org.apache.log4j.LogManager
import org.zaproxy.zap.session.ScriptBasedSessionManagementMethodType

val logger = LogManager.getLogger("session-template")

fun extractWebSession(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
    // Called only after an authentication request has been made
    // sessionWrapper.httpMessage will contain the request, response, user used for authentication
}

fun clearWebSessionIdentifiers(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
    // Handle custom clearing of sessions state when requested
}

fun processMessageToMatchSession(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
    // Called before every request. The sessionWrapper.httpMessage request can be modified before sending
    // to the web application
}

fun getRequiredParamsNames(): Array<String> {
    return emptyArray()
}

fun getOptionalParamsNames(): Array<String> {
    return arrayOf("sessionCheckUrl")
}
