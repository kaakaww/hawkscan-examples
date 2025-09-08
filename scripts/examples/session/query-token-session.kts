// HawkScan Session Script for Token-Based Authentication via Query Parameters
// This script manages session tokens by extracting them from authentication responses
// and automatically adding them as query parameters to subsequent requests

import org.apache.log4j.LogManager
import com.stackhawk.hste.session.ScriptBasedSessionManagementMethodType
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ObjectNode
import org.parosproxy.paros.network.HtmlParameter

// Initialize logger for debugging session management operations
val logger = LogManager.getLogger("query-token-session")
logger.info("Query Token Session script (query-token-session.kts) loaded successfully.")

// JSON parser for extracting token from authentication response
val mapper = ObjectMapper()

/**
 * Session Extraction Function
 * 
 * Called after authentication to establish a session. Extracts the authentication token
 * from the JSON response body and stores it for use in subsequent requests.
 * 
 * The sessionWrapper provides access to:
 * - httpMessage.responseBody: JSON response containing the token
 * - httpMessage.responseHeader: HTTP headers from auth response
 * - httpMessage.requestingUser: User making the authenticated request
 * 
 * @param sessionWrapper Contains the authentication response data
 */
fun extractWebSession(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
    val responseBody = sessionWrapper.httpMessage.responseBody
    logger.info("Got authentication response:\n${responseBody}")
    
    // Parse JSON response to extract the token field
    val authResponseObject = mapper.readValue(sessionWrapper.httpMessage.responseBody.bytes, ObjectNode::class.java)
    val token = authResponseObject.get("Token").asText()
    logger.info("Extracted authorization session token from authN response:\ntoken = $token")
    
    // Store token in session for use by processMessageToMatchSession()
    sessionWrapper.session.setValue("token", token)
}

/**
 * Request Modification Function
 * 
 * Called for each outgoing request to modify it before sending to the web application.
 * This function automatically adds the authentication token as a query parameter to
 * maintain the authenticated session state.
 * 
 * Process:
 * 1. Retrieves the stored session token
 * 2. Removes any existing "token" query parameter to avoid duplicates
 * 3. Adds the current session token as a URL query parameter
 * 4. Updates the request with modified parameters
 * 
 * @param sessionWrapper Contains the outgoing HTTP request to be modified
 */
fun processMessageToMatchSession(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
    // Get the session token that was stored during authentication
    val sessionToken = sessionWrapper.session.getValue("token").toString()
    val queryParams = sessionWrapper.httpMessage.urlParams
    
    // Remove any existing token parameter to prevent duplicates
    if (queryParams.find { it.name == "token" } != null) {
        queryParams.removeIf { it.name == "token" }
    }
    
    // Add the current session token as a query parameter
    queryParams.add(HtmlParameter(HtmlParameter.Type.url, "token", sessionToken))
    
    // Apply the updated parameters to the request
    sessionWrapper.httpMessage.requestHeader.setGetParams(queryParams)
}

/**
 * Session Cleanup Function
 * 
 * Called internally when a new session is required, typically after session expiry
 * or logout. This function should clear any stored session identifiers to prepare
 * for a fresh authentication cycle.
 * 
 * Note: This implementation is empty as token cleanup is handled automatically
 * when a new token is extracted during re-authentication.
 * 
 * @param sessionWrapper Contains the session data to be cleared
 */
fun clearWebSessionIdentifiers(sessionWrapper: ScriptBasedSessionManagementMethodType.SessionWrapper) {
    // No explicit cleanup needed - session token will be overwritten on next auth
}

/**
 * Required Parameters Configuration
 * 
 * Defines the parameter names that must be provided in the stackhawk.yml configuration
 * under sessionScript.parameters. The script will fail to load if these are missing.
 * 
 * This script currently requires no external parameters as it extracts all needed
 * information from the authentication response.
 * 
 * @return Array of required parameter names (empty for this script)
 */
fun getRequiredParamsNames(): Array<String> {
    return arrayOf()
}

/**
 * Optional Parameters Configuration
 * 
 * Defines the parameter names that can optionally be provided in the stackhawk.yml
 * configuration under sessionScript.optionalParameters. The script will not fail
 * if these parameters are missing.
 * 
 * This script currently uses no optional parameters.
 * 
 * @return Array of optional parameter names (empty for this script)
 */
fun getOptionalParamsNames(): Array<String> {
    return arrayOf()
}
