import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.databind.JsonNode
import com.nimbusds.jwt.SignedJWT
import com.stackhawk.hste.extension.talon.cleanHost
import com.stackhawk.hste.extension.talon.hawkscan.ExtensionTalonHawkscan
import java.time.Instant
//import java.time.Duration.between
import org.apache.log4j.LogManager
import com.stackhawk.hste.session.ScriptBasedSessionManagementMethodType
import org.parosproxy.paros.network.HttpMessage
import org.parosproxy.paros.network.HttpRequestHeader
import org.parosproxy.paros.network.HttpHeader
import org.apache.commons.httpclient.Cookie
import org.apache.commons.httpclient.URI
import org.parosproxy.paros.control.Control
import kotlin.system.exitProcess
import org.parosproxy.paros.network.HttpSender

val logger = LogManager.getLogger("external-auth-session")
val mapper = ObjectMapper()
val talon = Control
    .getSingleton()
    .extensionLoader
    .getExtension(ExtensionTalonHawkscan::class.java)

fun extractWebSession(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
    logger.info("Extracting session data from external command authentication response")

    try {
        val responseBody = sessionWrapper.httpMessage.responseBody.toString()
        logger.debug("External command output: $responseBody")

        val jsonObject = mapper.readValue(responseBody.toByteArray(), ObjectNode::class.java)

        // Validate required structure - must have headers or cookies (matching HawkScan's expectation)
        val headers = jsonObject.get("headers")
        val cookies = jsonObject.get("cookies")

        if (headers == null && cookies == null) {
            throw IllegalArgumentException("External command output must contain 'headers' and/or 'cookies' arrays. " +
                "Expected format: {\"headers\": [{\"key\": \"value\"}], \"cookies\": [{\"key\": \"value\"}]}")
        }

        // Extract cookies from external command JSON (HawkScan format)
        extractExternalCommandCookies(cookies, sessionWrapper)

        // Extract headers from external command JSON (HawkScan format)
        extractExternalCommandHeaders(headers, sessionWrapper)

        logger.info("Session extraction from external command completed successfully")

        // Validate the extracted session data by testing against the validation endpoint
        validateSession(sessionWrapper)

    } catch (e: Exception) {
        logger.error("Error extracting web session from external command output: ${e.message}", e)
        throw e
    }

}

fun validateSession(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
    logger.info("Validating extracted session data against validation endpoint")

    try {
        // Get validation parameters from session wrapper

        val validationUrl = sessionWrapper.getParam("validation_url")
        val validationRegex = sessionWrapper.getParam("validation_regex")

        if (validationUrl.isNullOrEmpty()) {
            logAndExit("Validation URL parameter 'validation_url' is required but not provided")
        }

        if (validationRegex.isNullOrEmpty()) {
            logAndExit("Validation regex parameter 'validation_regex' is required but not provided")
        }

        logger.debug("Validation URL: $validationUrl")
        logger.debug("Validation regex: $validationRegex")

        // Create a new HttpMessage for validation
        val validationMessage = HttpMessage()
        validationMessage.requestHeader = HttpRequestHeader(
            HttpRequestHeader.GET,
            URI(validationUrl, false),
            HttpHeader.HTTP11
        )


        // Set up the validation message with the same user context for cookie handling
        validationMessage.requestingUser = sessionWrapper.httpMessage.requestingUser

        // Copy cookies from the session's HttpState to the validation message
        val cookies = sessionWrapper.session.httpState.cookies
        if (cookies.isNotEmpty()) {
            logger.debug("Copying ${cookies.size} cookies to validation request")
            // The cookies will be automatically handled by the HttpState
        } else {
            logger.debug("No cookies to add to validation request")
        }

        // Apply all extracted headers to the validation request
        addHeadersToRequest(sessionWrapper, validationMessage)

        // Send the validation request using HawkScan's HTTP infrastructure
        try {
            logger.debug("Executing validation request...")

            // Log what we're sending for debugging
            logger.info("Sending validation request to: $validationUrl")
            val headerCount = sessionWrapper.session.getValue("header_names")?.toString()?.split(",")?.size ?: 0
            logger.info("Including $headerCount authentication headers")

            logger.debug(validationMessage.requestHeader.toString())

            // Actually send the HTTP request
            // Use a simple HttpSender approach
            val httpSender = HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR)
            httpSender.sendAndReceive(validationMessage, true)

            logger.debug(/* message = */ "Validation request completed with status:\n" +
                    validationMessage.responseHeader.toString() + "\n\n" +
                    validationMessage.responseBody.toString()
            )

        } catch (e: Exception) {
            logger.error("Failed to send validation request: ${e.message}")
            throw e
        }

        // Check the response against the validation regex
        val response = validationMessage.responseHeader.toString() + validationMessage.responseBody.toString()
        val regex = Regex(validationRegex)

        logger.debug("Validation response: ${validationMessage.responseHeader.primeHeader}")
        logger.debug("Response body length: ${validationMessage.responseBody.length()}")

        if (regex.containsMatchIn(response)) {
            val successMsg = "Session validation SUCCESSFUL - response matches pattern '$validationRegex'"
            logger.info(successMsg)
            println("SUCCESS: $successMsg")
            logger.info("Validation response status: ${validationMessage.responseHeader.statusCode}")
        } else {
            val errorMsg = "Session validation FAILED - response does not match pattern '$validationRegex'. " +
                "Status: ${validationMessage.responseHeader.statusCode}, " +
                "Response: ${validationMessage.responseHeader.primeHeader}"
            logger.debug("Full response body: ${validationMessage.responseBody}")
            logAndExit(errorMsg)
        }

    } catch (e: Exception) {
        logAndExit("Session validation failed with exception: ${e.message}")
    }
}

fun extractExternalCommandCookies(cookiesNode: JsonNode?, sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
    if (cookiesNode == null) {
        logger.debug("No cookies found in external command output")
        return
    }

    logger.debug("Extracting cookies from external command output")
    val domain = getDomainFromConfig()
    val cookieMap = extractKeyValuePairs(cookiesNode)

    cookieMap.map { (name, value) ->
        addCookieToSession(sessionWrapper, name, value, domain)
    }
    val cookieCount = cookieMap.count()

    if (cookieCount > 0) {
        logger.info("Added $cookieCount cookies from external command to HttpState - they will be automatically included in requests")
        logActiveCookies(sessionWrapper)
    }
}

fun extractExternalCommandHeaders(headersNode: JsonNode?, sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
    if (headersNode == null) {
        logger.debug("No headers found in external command output")
        return
    }

    logger.debug("Extracting headers from external command output")
    val headers = extractKeyValuePairs(headersNode)

    if (headers.isNotEmpty()) {
        // Store headers using the new abstraction
        setSessionValues(sessionWrapper, headers, "header_")

        // Store header names for later retrieval
        sessionWrapper.session.setValue("header_names", headers.keys.joinToString(","))

        // Handle JWT token if Authorization header is present
        val authHeader = headers["Authorization"]
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            sessionWrapper.session.setValue("auth_header", authHeader)

            // Parse and store JWT claims for expiration checking
            withErrorLogging("JWT token parsing") {
                val token = authHeader.substring(7) // Remove "Bearer " prefix
                if (isJWT(token)) {
                    val jwt = SignedJWT.parse(token)
                    val expirationTime = jwt.jwtClaimsSet.expirationTime
                    if (expirationTime != null) {
                        sessionWrapper.session.setValue("jwt_expires_at", expirationTime.time.toString())
                        logger.info("JWT token stored - expires at: $expirationTime")
                    }
                }
            }

            logger.info("Authorization header stored - JWT handling via script session management")
        }

        logger.info("Stored ${headers.size} headers in script session")
    }
}

fun processMessageToMatchSession(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
    logger.debug("Processing message to match session from external command data")

    try {
        // Handle JWT expiration checking using stored JWT expiration time
        handleJWTExpiration(sessionWrapper)

        // Apply all headers from session to the current request
        addHeadersToRequest(sessionWrapper, sessionWrapper.httpMessage)

        // Cookies are automatically handled by HttpState - no manual intervention needed!
        logger.debug("Cookies automatically managed by HttpState")

        logger.debug("Message processing completed")

    } catch (e: Exception) {
        logger.error("Error processing message to match session: ${e.message}", e)
    }
}

fun handleJWTExpiration(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
    try {
        val jwtExpiresAt = sessionWrapper.session.getValue("jwt_expires_at")?.toString()?.toLongOrNull()

        if (jwtExpiresAt != null) {
            val expirationTime = Instant.ofEpochMilli(jwtExpiresAt)
            val currentTime = Instant.now()
            val refreshBuffer = 300L // Refresh 5 minutes before expiration

            logger.debug("JWT token expires at: $expirationTime")

            if (currentTime.isAfter(expirationTime.minusSeconds(refreshBuffer))) {
                logger.warn("JWT token is expired or about to expire - triggering re-authentication")
                synchronized(this) {
                    // Clear expired JWT data
                    sessionWrapper.session.setValue("auth_header", null)
                    sessionWrapper.session.setValue("jwt_expires_at", null)

                    // Trigger re-authentication
                    sessionWrapper.httpMessage.requestingUser.authenticate()
                }
            } //else {
              //  val timeUntilExpiration = java.time.Duration.between(currentTime, expirationTime)
              //  logger.debug("JWT token valid for ${timeUntilExpiration.toMinutes()} more minutes")
            //}
        }
    } catch (e: Exception) {
        logger.debug("Error checking JWT expiration: ${e.message}")
    }
}

fun getDomainFromConfig(): String {
    return talon.talonHawkScanConf.hawkscanConf.app.cleanHost()
}

fun getDefaultDomain(): String {
    // Could be configurable in the future, but localhost is a safe default
    return "localhost"
}

fun logActiveCookies(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
    try {
        val cookies = sessionWrapper.session.httpState.cookies
        if (cookies.isNotEmpty()) {
            logger.debug("Active cookies in HttpState:")
            cookies.forEach { cookie ->
                logger.debug("  ${cookie.name}=${cookie.value} (domain: ${cookie.domain}, path: ${cookie.path})")
            }
        } else {
            logger.debug("No active cookies in HttpState")
        }
    } catch (e: Exception) {
        logger.debug("Error logging active cookies: ${e.message}")
    }
}

// Generic JSON processing utilities
fun extractKeyValuePairs(node: JsonNode?): Map<String, String> {
    if (node == null) return emptyMap()

    val result = mutableMapOf<String, String>()

    if (node.isArray) {
        node.forEach { item ->
            if (item.isObject) {
                item.fields().forEach { (key, value) ->
                    result[key] = value.asText()
                }
            }
        }
    } else if (node.isObject) {
        node.fields().forEach { (key, value) ->
            result[key] = value.asText()
        }
    }

    return result
}

// Combined cookie creation and addition
fun addCookieToSession(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper, name: String, value: String, domain: String): Int {
    return try {
        val cookie = Cookie(
            domain,     // domain
            name,       // name
            value,      // value
            "/",        // path (default to root)
            null,       // expiration (null = session cookie)
            false       // secure (default false)
        )

        sessionWrapper.session.httpState.addCookie(cookie)
        logger.debug("Added cookie to HttpState: $name (domain: $domain)")
        1 // Return count of cookies added
    } catch (e: Exception) {
        logger.error("Failed to add cookie $name: ${e.message}")
        0
    }
}

// Header names processing abstraction

// Session value management utilities
fun clearSessionValues(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper, valuePrefix: String): Int {
    val headerNames = sessionWrapper.session.getValue("header_names")?.toString()?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()
    var clearedCount = 0

    headerNames.forEach { headerName ->
        try {
            sessionWrapper.session.setValue("${valuePrefix}${headerName}", null)
            clearedCount++
        } catch (e: Exception) {
            logger.error("Failed to clear session value ${valuePrefix}${headerName}: ${e.message}")
        }
    }

    return clearedCount
}

fun setSessionValues(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper, values: Map<String, String>, prefix: String = "") {
    values.forEach { (key, value) ->
        try {
            sessionWrapper.session.setValue("$prefix$key", value)
        } catch (e: Exception) {
            logger.error("Failed to set session value $prefix$key: ${e.message}")
        }
    }
}

// Error handling abstractions
fun <T> withErrorLogging(operation: String, block: () -> T): T? {
    return try {
        block()
    } catch (e: Exception) {
        logger.error("Error during $operation: ${e.message}", e)
        null
    }
}

fun logAndExit(message: String, exitCode: Int = 1) {
    logger.error(message)
    println("ERROR: $message")
    exitProcess(exitCode)
}

fun addHeadersToRequest(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper, message: HttpMessage) {
    val headerNames = sessionWrapper.session.getValue("header_names")?.toString()?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()
    //logger.debug("Header names: $headerNames")
    var addedCount = 0

    headerNames.forEach { headerName ->
        val headerValue = sessionWrapper.session.getValue("header_${headerName}").toString()
        if (headerValue.isNotEmpty()) {
            message.requestHeader.setHeader(headerName, headerValue)
            logger.debug("Added header to request: $headerName")
            addedCount++
        }
    }
    if (addedCount > 0) {
        logger.debug("Added $addedCount headers to request")
    }
}

fun clearWebSessionIdentifiers(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
    logger.info("Clearing external command session identifiers")

    // Clear cookies from HttpState (automatic cookie management)
    withErrorLogging("clearing cookies from HttpState") {
        val cookieCountBefore = sessionWrapper.session.httpState.cookies.size
        sessionWrapper.session.httpState.clearCookies()
        logger.debug("Cleared $cookieCountBefore cookies from HttpState")
    }

    // Clear headers from session values using new abstraction
    val headerCount = clearSessionValues(sessionWrapper, "header_")

    // Clear header tracking
    withErrorLogging("clearing header names tracking") {
        sessionWrapper.session.setValue("header_names", null)
    }

    logger.debug("Cleared $headerCount headers from session values")

    // Clear JWT data
    withErrorLogging("clearing JWT data from session") {
        sessionWrapper.session.setValue("auth_header", null)
        sessionWrapper.session.setValue("jwt_expires_at", null)
        logger.debug("Cleared JWT data from session")
    }

    logger.info("External command session identifiers cleared")
}

fun isJWT(token: String): Boolean {
    return token.split('.').size == 3 && token.contains('.')
}

fun getRequiredParamsNames(): Array<String> {
    return arrayOf("validation_url", "validation_regex")
}

fun getOptionalParamsNames(): Array<String> {
    return arrayOf(
        // External command session management doesn't require additional parameters
        // as it extracts data directly from the command's JSON output structure
    )
}