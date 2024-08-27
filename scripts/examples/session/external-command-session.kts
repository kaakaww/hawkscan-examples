import org.apache.log4j.LogManager
import org.apache.log4j.Logger
import com.stackhawk.hste.session.ScriptBasedSessionManagementMethodType
import com.stackhawk.hste.extension.script.ScriptVars

/* external-command-session.kts
 *  This HawkScan session script runs an external command for every request, and adds any cookies or headers returned
 *  from the external command to the current scanner request.
 *
 *  Required params:
 *      sessionCommand - the relative path to the external command to run
 *  Optional params:
 *      inputData - a string that will be passed to the external command environment as the env var, INPUT_DATA
 *
 *  External Command Inputs (via environment variables):
 *      INPUT_DATA - The data from the inputData param
 *      MSG_HEADERS - The headers from the current HTTP message
 *      MSG_BODY - The body from the current HTTP message
 *  External Command Outputs:
 *      The external command is expected to output a JSON blob to std-out containing any headers or cookies to add to
 *      the current request. See https://tinyurl.com/yjeeswwf for an example.
 */

val logger: Logger = LogManager.getLogger("external-command-session")

// This function is called after the authentication function to establish a session.
// The sessionWrapper.httpMessage will contain the responseBody, responseHeader and requestingUser which can be used to
// gather data pertaining to the authentication status such as cookies, tokens or data from the responseBody
fun extractWebSession(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
    /* We assume that authentication has been already been handled. In this script, our only concern is to further
     * modify requests during scanning. So there's nothing to do here.
     */
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
    return arrayOf("sessionCommand")
}

fun getOptionalParamsNames(): Array<String> {
    return arrayOf("inputData")
}