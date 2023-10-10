import org.apache.commons.httpclient.URI
import org.apache.log4j.LogManager
import org.parosproxy.paros.network.HttpHeader
import org.parosproxy.paros.network.HttpMessage
import org.parosproxy.paros.network.HttpRequestHeader
import org.zaproxy.zap.authentication.AuthenticationHelper
import org.zaproxy.zap.authentication.GenericAuthenticationCredentials
import org.zaproxy.zap.network.HttpRequestBody
import java.io.ByteArrayInputStream
import java.io.File
import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.util.Locale
import javax.xml.bind.DatatypeConverter
import com.nimbusds.jwt.JWTClaimsSet
import java.util.Date
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.SignedJWT
import java.net.URLEncoder

val logger = LogManager.getLogger("AAD-CC-Auth-Script")

// This function is called before a scan is started and when the loggedOutIndicator is matched indicating re-authentication is needed.
fun authenticate(
    helper: AuthenticationHelper,
    paramsValues: Map<String, String>,
    credentials: GenericAuthenticationCredentials
): HttpMessage {
    logger.info("AAD Client Credentials Authentication: Go!")

    val baseUrl = "https://login.microsoftonline.com"
    val tenant = paramsValues["tenant"]
    val scope = paramsValues["scope"]
    val clientId = credentials.getParam("clientId")
    val grantType = "client_credentials"
    val certThumbprint = paramsValues["cert_thumbprint"]
    val openidConfigEndpoint = "${baseUrl}/${tenant}/v2.0/.well-known/openid-configuration"
    val tokenEndpoint = "${baseUrl}/${tenant}/oauth2/v2.0/token"
    val assertionType = URLEncoder.encode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "UTF-8")
    val client_assertion = getJwtToken(tokenEndpoint, clientId, certThumbprint!!)
    val authRequestBody = "client_id=${clientId}&client_assertion_type=${assertionType}&grant_type=${grantType}&scope=${scope}&client_assertion=${client_assertion}"

    logger.info("OpenID Configuration Endpoint: $openidConfigEndpoint")
    logger.info("Token Endpoint: $tokenEndpoint")

    val msg = helper.prepareMessage()
    msg.requestHeader = HttpRequestHeader(
        HttpRequestHeader.POST,
        URI(tokenEndpoint, false),
        HttpHeader.HTTP11
    )
    msg.requestHeader.setHeader("Content-Type", "application/x-www-form-urlencoded")
    msg.requestHeader.setHeader("Accept", "application/json")
    msg.requestHeader.setHeader("Cache-control", "no-cache")
    msg.requestBody = HttpRequestBody(authRequestBody)
    msg.requestHeader.contentLength = msg.requestBody.length()

    helper.sendAndReceive(msg)
    logger.info("Auth Request:\n=== REQUEST HEADERS ===\n${msg.requestHeader}\n=== REQUEST BODY ===\n${msg.requestBody}\n")
    logger.info("Auth Response:\n=== RESPONSE HEADERS ===\n${msg.responseHeader}\n=== RESPONSE BODY ===\n${msg.responseBody}\n")

    return msg
}

// The required parameter names for your script, your script will throw an error if these are not supplied in the script.parameters configuration.
// Add these parameters to your HawkScan configuration file under app.authentication.script.parameters.
fun getRequiredParamsNames(): Array<String> {
    /**
     * @return
     *      tenant: The directory tenant that you want to log the user into. The tenant can be in GUID or friendly name format
     *      scope:  A space-separated list of scopes, or permissions, that the app requires
     */
    return arrayOf("tenant", "scope", "audience_url", "cert_thumbprint")
}

// The required credential parameters, your script will throw an error if these are not supplied in the script.credentials configuration.
// Add these credential parameters to your HawkScan configuration file under app.authentication.script.credentials.
fun getCredentialsParamsNames(): Array<String> {
    /**
     * @return
     *      clientId:       The Application (client) ID that the Azure portal - App registrations page assigned to your app
     *      clientSecret:   The client secret that you generated for your app in the app registration portal
     */
    return arrayOf("clientId")
}

// Add these optional parameters to your HawkScan configuration file under app.authentication.script.parameters.
fun getOptionalParamsNames(): Array<String> {
    return arrayOf()
}


fun getJwtToken(aud : String, iss : String, x5t : String) : Base64URL {
    val nbf  = Date()
    val iat = nbf
    //Add 5 mintues
    val exp = Date(nbf.time + (5 * 60 * 1000))
    val jwtId = "Testing"
    val claimseSet = JWTClaimsSet.Builder()
        .subject(iss)
        .issuer(iss)
        .notBeforeTime(nbf)
        .issueTime(iat)
        .expirationTime(exp)
        .jwtID(jwtId)
        .audience(aud)
        .build()

    val typ = "JWT"

    val header = JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType(typ)).x509CertThumbprint(Base64URL(x5t)).build()

    val jwt = SignedJWT(header, claimseSet)

    return jwt.signature
}


fun getThumbrintFromCert(certPath : String) : String {
    val certificateFactory = CertificateFactory.getInstance("X.509")
    val certStream = ByteArrayInputStream(File(certPath).readBytes())
    val cert: Certificate = certificateFactory.generateCertificate(certStream)
    val thumbrint = getThumbprint(cert)
    return thumbrint
}


fun getThumbprint(cert: Certificate): String {
    val md = MessageDigest.getInstance("SHA-1")
    val der: ByteArray = cert.getEncoded()
    md.update(der)
    val digest = md.digest()
    val digestHex = DatatypeConverter.printHexBinary(digest)
    return digestHex.lowercase(Locale.getDefault())
}