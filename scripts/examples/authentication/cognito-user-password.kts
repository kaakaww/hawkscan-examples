import org.parosproxy.paros.network.HttpMessage
import org.zaproxy.zap.authentication.AuthenticationHelper
import org.zaproxy.zap.authentication.GenericAuthenticationCredentials
import org.zaproxy.zap.network.HttpRequestBody
import org.apache.commons.httpclient.URI
import org.apache.log4j.LogManager
import org.parosproxy.paros.network.HttpHeader
import org.parosproxy.paros.network.HttpRequestHeader

val logger = LogManager.getLogger("Cognito_Auth_Logger")

// set up some static string variables for code completion and ease of maintenance
val CREDS_USER = "username"
val CREDS_PASS = "password"
val CREDS_CLIENT = "client_id"
val PARAM_AUTHFLOW = "auth_flow"
val PARAM_PROVIDER = "auth_provider"

// script entry point
fun authenticate(
    helper: AuthenticationHelper,
    paramsValues: Map<String, String>,
    credentials: GenericAuthenticationCredentials
): HttpMessage {
    logger.info("Cognito Auth Script starting...");

    // build request header and body based on documentation here:
    // https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html
    // depending on your user pools config, this could require a two/multi challenge process; this example shows the basic
    // one step. Body structure may also vary depending on the version of Cognito.
    val requestUri = URI(paramsValues.get(PARAM_PROVIDER), false);
    val requestMethod = HttpRequestHeader.POST;
    val requestHeader = HttpRequestHeader(requestMethod, requestUri, HttpHeader.HTTP11);
    requestHeader.setHeader("X-Amz-Target", "AWSCognitoIdentityProviderService.InitiateAuth");
    requestHeader.setHeader("Content-Type", "application/x-amz-json-1.1");
    requestHeader.setHeader("Accept", "application/json");
    requestHeader.setHeader("Cache-control", "no-cache");

    //build request body
    val requestBody = """
        {
          "AuthFlow": "${paramsValues.get(PARAM_AUTHFLOW)}", 
          "AuthParameters": {
            "USERNAME": "${credentials.getParam(CREDS_USER)}", 
            "PASSWORD": "${credentials.getParam(CREDS_PASS)}", 
            "ClientId": "${credentials.getParam(CREDS_CLIENT)}"
          }
        }""".trimIndent()

    // build post msg
    val msg = helper.prepareMessage();
    msg.requestHeader = requestHeader
    msg.requestBody = HttpRequestBody(requestBody)
    requestHeader.contentLength = msg.requestBody.length();

    //send and receive message
    helper.sendAndReceive(msg);
    logger.info("MSG SENT:\n${msg.requestHeader}\n\n${msg.requestBody}")
    logger.info("MSG RECV:\n${msg.responseHeader}\n\n${msg.responseBody}")

    return msg;
}


fun getRequiredParamsNames(): Array<String> {
    return arrayOf(PARAM_AUTHFLOW, PARAM_PROVIDER)
}

fun getOptionalParamsNames(): Array<String> {
    return emptyArray<String>();
}

fun getCredentialsParamsNames(): Array<String> {
    return arrayOf(CREDS_CLIENT, CREDS_USER, CREDS_PASS)
}
