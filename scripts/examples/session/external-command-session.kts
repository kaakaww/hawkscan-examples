import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import org.apache.log4j.LogManager
import org.apache.log4j.Logger
import com.stackhawk.hste.session.ScriptBasedSessionManagementMethodType
import com.stackhawk.hste.extension.script.ScriptVars
import org.apache.commons.httpclient.Cookie
import java.io.BufferedReader
import java.io.InputStreamReader

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

val COOKIE_KEY = "cookies"
val HEADER_KEY = "headers"

private val mapper = ObjectMapper()

// This function is called after the authentication function to establish a session.
// The sessionWrapper.httpMessage will contain the responseBody, responseHeader and requestingUser which can be used to
// gather data pertaining to the authentication status such as cookies, tokens or data from the responseBody
fun extractWebSession(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
    /* We assume that authentication has been already been handled. In this script, our only concern is to further
     * modify requests during scanning. So there's nothing to do here.
     */
    val msg = sessionWrapper.httpMessage
    try {

        val jsonObject = mapper.readValue(msg?.responseBody.toString(), ObjectNode::class.java)
        val headers = jsonObject[HEADER_KEY]
        val cookies = jsonObject[COOKIE_KEY]
        val injectableHeaders = mutableMapOf<String, String>()

        if (headers == null && cookies == null) throw Exception("Invalid Format")

        headers?.forEachIndexed { index, jsonNode ->
            val keys: Iterator<String> = jsonNode.fieldNames()

            while (keys.hasNext()) {
                val key = keys.next()
                logger.debug("Adding header ${key} : ${jsonNode.get(key).asText()}")
                injectableHeaders[key] = jsonNode.get(key).asText()
                ScriptVars.setGlobalVar("tokenName$index", key)
                ScriptVars.setGlobalVar("tokenValue$index", jsonNode.get(key).asText())
            }
        }
        // sessionWrapper.session.headers = injectableHeaders
        cookies?.forEach {
            val keys = it.fieldNames()

            while (keys.hasNext()) {
                val key = keys.next()
                val httpCookie =
                    Cookie(
                        // TODO: replace this one with the actual domain
                        "http://localhost",
                        key,
                        it.get(key).asText(),
                    )

                logger.debug("Adding session cookie ${httpCookie.name} wtih value ${httpCookie.value}")
                sessionWrapper.session.httpState.addCookie(httpCookie)
            }
        }
    } catch (ex: Exception) {
        throw ex
    }
}

// This function is called on each request allow the request to be modified before it is sent to the web application.
fun processMessageToMatchSession(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
    var tokenIterator = 0
    logger.info("Setting token headers")
    while (ScriptVars.getGlobalVars().containsKey("tokenName$tokenIterator")) {
        logger.info(
            "Adding session token ${ScriptVars.getGlobalVar("tokenName$tokenIterator")} with value ${
                ScriptVars.getGlobalVar(
                    "tokenValue$tokenIterator"
                )
            }"
        )
        sessionWrapper.httpMessage.requestHeader.addHeader(
            ScriptVars.getGlobalVar("tokenName$tokenIterator"),
            ScriptVars.getGlobalVar("tokenValue$tokenIterator")
        )
        tokenIterator++
    }
    try {

        logger.info("Starting special process")
        var processCommand = sessionWrapper.getParam("sessionCommand").split(" ").toMutableList()

        processCommand.add(sessionWrapper.getParam("client_id"))
        processCommand.add(sessionWrapper.getParam("private_key"))
        processCommand.add(sessionWrapper.getParam(sessionWrapper.httpMessage.requestBody.toString()))
        processCommand.add(sessionWrapper.getParam(sessionWrapper.httpMessage.requestHeader.method.toString()))
        processCommand.add(sessionWrapper.getParam(sessionWrapper.httpMessage.requestHeader.uri.toString()))

        logger.debug("Running this command: ${processCommand.joinToString(" ")}")

        var cmdOutput = runProcess(processCommand)

        val jsonObject = mapper.readValue(cmdOutput, ObjectNode::class.java)
        val headers = jsonObject[HEADER_KEY]
        val cookies = jsonObject[COOKIE_KEY]

        if (headers == null && cookies == null) throw Exception("Invalid Format")

        headers?.forEachIndexed { index, jsonNode ->
            val keys: Iterator<String> = jsonNode.fieldNames()

            while (keys.hasNext()) {
                val key = keys.next()
                logger.debug("Adding header ${key} : ${jsonNode.get(key).asText()}")
                sessionWrapper.httpMessage.requestHeader.addHeader(key, jsonNode.get(key).asText())
            }
        }
    } catch (e: Exception) {
        logger.error(e.printStackTrace())

    }
}

    // Called internally when a new session is required
    fun clearWebSessionIdentifiers(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
    }

    // The required parameter names for your script, your script will throw an error if these are not supplied in the sessionScript.parameters configuration.
    fun getRequiredParamsNames(): Array<String> {
        return arrayOf("externalCommand")
    }

    fun getOptionalParamsNames(): Array<String> {
        return arrayOf("client_id", "private_key")
    }


fun runProcess(command: List<String>): String {
    val processBuilder = ProcessBuilder()
    processBuilder.command(*command.map { it }.toTypedArray())
    try {

        logger.debug("Starting command process")
        val process: Process = processBuilder.start()

        logger.debug("Waiting for command process")
        val exitVal = process.waitFor()
        logger.debug("Command process finished")
        if (exitVal == 0) {
            val cmdOutput = String(process.inputStream.readAllBytes())
            logger.debug(cmdOutput)
            return cmdOutput
        } else {
            logger.error("Non zero exit code $exitVal")
            logger.error(String(process.errorStream.readAllBytes()))
            throw Exception("Authentication failed with a non zero output")
        }
    } catch (e: Exception) {
        logger.error(e.printStackTrace())
        throw e
    }
}
