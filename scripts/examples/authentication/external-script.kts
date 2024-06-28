import org.apache.commons.httpclient.URI
import org.apache.log4j.LogManager
import org.parosproxy.paros.network.HttpHeader
import org.parosproxy.paros.network.HttpMessage
import org.parosproxy.paros.network.HttpRequestHeader
import com.stackhawk.hste.authentication.AuthenticationHelper
import com.stackhawk.hste.authentication.GenericAuthenticationCredentials
import com.stackhawk.hste.extension.script.ScriptVars
import java.io.InputStreamReader
import java.io.BufferedReader
import java.io.FileInputStream
import java.net.HttpCookie


val logger = LogManager.getLogger("external-script")


fun getLoggedOutIndicator() : String {
    return ".*Location:.*/login.*"
}

fun getLoggedInIndicator() : String {
    return "\\QSign Out\\E"
}


// This function is called before a scan is started and when the loggedOutIndicator is matched indicating re-authentication is needed.
fun authenticate(
    helper: AuthenticationHelper,
    paramsValues: Map<String, String>,
    credentials: GenericAuthenticationCredentials
): HttpMessage {
    var authFile = paramsValues["auth_script_file"]
    val processBuilder = ProcessBuilder()
    // Build command to run script
    processBuilder.command("bash", "-c", authFile)

    val testPath = paramsValues["test_path"]

    var msg = helper.prepareMessage();
    var requestUri = URI(testPath, false);
    var requestMethod = HttpRequestHeader.GET

    var requestHeader = HttpRequestHeader(requestMethod, requestUri, HttpHeader.HTTP11)

    try {

        logger.info("Starting special process")
        val process: Process = processBuilder.start()
        val reader = BufferedReader(InputStreamReader(process.inputStream))
        val errorReader = BufferedReader(InputStreamReader(process.errorStream))


        logger.info(reader.readText())




        logger.info("waiting for process")
        val exitVal = process.waitFor()
        logger.info("process finished")
        if (exitVal == 0) {
            if (paramsValues.containsKey("cookie_file")) {
                val cookieFile = paramsValues["cookie_file"]

                cookieFile?.let {
                    readAndInjectCookies(it, requestHeader)
                }

            }

            if (paramsValues.containsKey("token_file")) {
                val tokenFile = paramsValues["token_file"]

                tokenFile?.let {
                    logger.info("This is the name of the token file $it}")
                    readAndInjectTokens(it, requestHeader)
                }
            }

        } else {
            logger.info("There was an issue processing the file")
            logger.error(errorReader.readText())
        }
    } catch (e: Exception) {
        logger.info(e.printStackTrace())
        throw e
    }

    requestHeader.contentLength = msg.requestBody.length();

    msg.requestHeader = requestHeader;

    logger.info("Request Header ${msg.requestHeader}")
    logger.info("Request Body ${msg.requestBody}")
    helper.sendAndReceive(msg)

    logger.info("Response Header ${msg.responseHeader}")
    logger.info("Response Bodye ${msg.responseBody}")
    return msg

}

fun readAndInjectAuth(file : String, type: String, requestHeader: HttpRequestHeader) {
    val reader = FileInputStream(file).bufferedReader()
    val iterator = reader.lines().iterator()
    var i = 0;
    while (iterator.hasNext()) {
        val line = iterator.next()
        logger.info(line)
        readLineAndAddToken(line, type, requestHeader, i)
        i++
    }

}

fun readAndInjectCookies(file : String, requestHeader: HttpRequestHeader) {
    readAndInjectAuth(file, "cookie", requestHeader )
}

fun readAndInjectTokens(file : String, requestHeader: HttpRequestHeader) {
    readAndInjectAuth(file, "token", requestHeader )
}

fun readLineAndAddToken(line : String, type : String, httpRequestHeader: HttpRequestHeader, iterator: Int) {
    val token = splitString(line)
    token?.let {
        addValueToScriptVar(it.first, it.second, type, iterator)
        when (type) {
            "token" -> addTokenToHeader(httpRequestHeader, it.first, it.second)
            "cookie" -> addCookieToMessage(httpRequestHeader, HttpCookie(it.first, it.second))
        }
    }
}

fun splitString(line : String) : Pair<String, String>? {
    line.split(" ").let{
        return Pair(it[0], it[1])
    }
}


fun addValueToScriptVar(name : String, value: String, type : String, iterator: Int) {
    ScriptVars.setGlobalVar("${type}Name$iterator", name)
    ScriptVars.setGlobalVar("${type}Value$iterator", value)
}

fun addCookieToMessage(requestHeader: HttpRequestHeader, cookie: HttpCookie) {
    val cookies = requestHeader.httpCookies
    cookies?.removeIf {it.name == cookie.name}
    cookies.add(cookie)
    logger.info("Adding cookie ${cookie.name} with value ${cookie.value}")
    requestHeader.setCookies(cookies)
}

fun addTokenToHeader(requestHeader: HttpRequestHeader, name : String, value : String) {
    logger.info("Adding header $name with value $value")
    requestHeader.setHeader(name, value)
}

// The required parameter names for your script, your script will throw an error if these are not supplied in the script.parameters configuration.
fun getRequiredParamsNames(): Array<String> {
    return arrayOf("test_path", "auth_script_file")
}

// The required credential parameters, your script will throw an error if these are not supplied in the script.credentials configuration.
fun getCredentialsParamsNames(): Array<String> {
    return arrayOf()
}

fun getOptionalParamsNames(): Array<String> {
    return arrayOf("cookie_file", "token_file")
}