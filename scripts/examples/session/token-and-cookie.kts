import org.apache.log4j.LogManager
import com.stackhawk.hste.authentication.GenericAuthenticationCredentials
import com.stackhawk.hste.extension.script.ScriptVars
import com.stackhawk.hste.session.ScriptBasedSessionManagementMethodType

val logger = LogManager.getLogger("token-and-cookie")

// This function is called after the authentication function to establish a session.
// The sessionWrapper.httpMessage will contain the responseBody, responseHeader and requestingUser which can be used to
// gather data pertaining to the authentication status such as cookies, tokens or data from the responseBody
fun extractWebSession(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
    // add the token name from the global var set during authentication script to the session
    sessionWrapper.session.setValue("authTokenName", ScriptVars.getGlobalVar("authTokenName"))

    // add the token value from the auth credentials to the session for use in future requests
    val creds = sessionWrapper.httpMessage.requestingUser.authenticationCredentials as GenericAuthenticationCredentials
    sessionWrapper.session.setValue("authTokenValue", creds.getParam("authTokenValue"))

    // add cookies from auth to the session http state for use in future requests
    sessionWrapper.httpMessage.requestingUser?.authenticatedSession?.httpState?.cookies?.forEach { cookie ->
        logger.info("Adding cookie to request: ${cookie.name}=${cookie.value}")
        sessionWrapper.session.httpState.addCookie(cookie)
    }
}

// This function is called on each request allow the reuqest to be modified before it is sent to the web application.
fun processMessageToMatchSession(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
    // add the custom auth header to each request, cookies will be added automatically from the http state 
    sessionWrapper.httpMessage.requestHeader.addHeader(
        sessionWrapper.session.getValue("authTokenName") as String,
        sessionWrapper.session.getValue("authTokenValue") as String
    )
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
