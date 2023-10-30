import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
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
import java.net.URLEncoder
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.interfaces.RSAPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Date
import java.util.Locale
import java.util.UUID
import javax.xml.bind.DatatypeConverter

val logger = LogManager.getLogger("AAD-CCC-Auth-Script")


fun getLoggedOutIndicator() : String {
    return "^$"
}

fun getLoggedInIndicator() : String {
    return ".*"
}

// This function is called before a scan is started and when the loggedOutIndicator is matched indicating re-authentication is needed.
fun authenticate(
    helper: AuthenticationHelper,
    paramsValues: Map<String, String>,
    credentials: GenericAuthenticationCredentials
): HttpMessage {
    logger.info("AAD Client Credentials Authentication with Certificate: Go!")

    val baseUrl = "https://login.microsoftonline.com"
    val tenant = paramsValues["tenant"]
    val clientId = credentials.getParam("clientId")
    val scope = paramsValues["scope"] ?: "api://${clientId}/.default"
    val grantType = "client_credentials"
    val certPath = paramsValues["cert_path"]
    val openidConfigEndpoint = "${baseUrl}/${tenant}/v2.0/.well-known/openid-configuration"
    val tokenEndpoint = "${baseUrl}/${tenant}/oauth2/v2.0/token"
    val assertionType = URLEncoder.encode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "UTF-8")
    val pemKey = credentials.getParam("pem_key")
    val kid = paramsValues["kid"]
    val clientAssertion = getJwtToken(tokenEndpoint, clientId, certPath!!, pemKey!!, kid).serialize()
    logger.debug("here is the assertion $clientAssertion")
    val authRequestBody = "client_id=${clientId}&client_assertion_type=${assertionType}&grant_type=${grantType}&scope=${scope}&client_assertion=${clientAssertion}"

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

    if (msg?.responseHeader?.statusCode in 200..299) {
        return msg
    }
    throw(Exception("Authentication failed"))
}

// The required parameter names for your script, your script will throw an error if these are not supplied in the script.parameters configuration.
// Add these parameters to your HawkScan configuration file under app.authentication.script.parameters.
fun getRequiredParamsNames(): Array<String> {
    /**
     * @return
     *      tenant: The directory tenant that you want to log the user into. The tenant can be in GUID or friendly name format
     *      cert_path: Path to the certificate file in PEM format, e.g. `openssl pkcs12 -in {yourfile.pfx} -clcerts -nokeys -out yourcert.pem`
     */
    return arrayOf("tenant", "cert_path")
}

// The required credential parameters, your script will throw an error if these are not supplied in the script.credentials configuration.
// Add these credential parameters to your HawkScan configuration file under app.authentication.script.credentials.
fun getCredentialsParamsNames(): Array<String> {
    /**
     * @return
     *      clientId: The Application (client) ID that the Azure portal - App Registrations page assigned to your app
     *      pem_key: The client key in PEM format, e.g. `openssl pkcs12 -in {yourfile.pfx} -nocerts -nodes | openssl rsa`
     */
    return arrayOf("clientId", "pem_key")
}

// Add these optional parameters to your HawkScan configuration file under app.authentication.script.parameters.
fun getOptionalParamsNames(): Array<String> {
    /**
     * @return
     *      scope: The resource identifier (application ID URI) of the resource you want, affixed with the .default
     *          suffix, e.g. https://graph.microsoft.com/.default
     */
    return arrayOf("scope", "kid")
}


fun getJwtToken(aud : String, iss : String, certPath : String, pemKey : String, kid : String?) : SignedJWT {
    val nbf  = Date()
    val iat = nbf

    //Add 5 minutes
    val exp = Date(nbf.time + (5 * 60 * 1000))
    val jwtId = UUID.randomUUID().toString()
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

    val x5t = getThumbprintFromCert(certPath)
    val x5tHeader = Base64URL.encode(x5t.decodeHex())

    val keyID = kid ?: x5tHeader.toString()

    val headerBuilder = JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType(typ))
        .keyID(keyID)
        .x509CertThumbprint(x5tHeader)


    val header = headerBuilder.build()

    val jwt = SignedJWT(header, claimseSet)


    val signer = getSigner(readPrivateKey(pemKey))

    logger.info("now sign")
    jwt.sign(signer)

    logger.debug("Here is the jwt header: ${jwt.header}")
    logger.debug("Here is the jwt claims set: ${jwt.jwtClaimsSet}")
    logger.debug("Here is the jwt signature: ${jwt.signature}")

    return jwt
}

fun getSigner(privateKey : PrivateKey): RSASSASigner {
    logger.info("Here we are in private kye 2")

    return RSASSASigner(privateKey)
}



fun String.decodeHex(): ByteArray {
    check(length % 2 == 0) { "Must have an even length" }

    return chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()
}

//Reads private key from environment variable
fun readPrivateKey(key: String): RSAPrivateKey {
    val privateKeyPEM = key
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace(System.lineSeparator().toRegex(), "")
        .replace("-----END PRIVATE KEY-----", "")

    val encoded: ByteArray = Base64.from(privateKeyPEM).decode()
    val keyFactory = KeyFactory.getInstance("RSA")
    val keySpec = PKCS8EncodedKeySpec(encoded)
    return keyFactory.generatePrivate(keySpec) as RSAPrivateKey
}

fun getThumbprintFromCert(certPath : String) : String {
    val certificateFactory = CertificateFactory.getInstance("X.509")
    val certStream = ByteArrayInputStream(File(certPath).readBytes())
    val cert: Certificate = certificateFactory.generateCertificate(certStream)
    val thumbrint = getThumbprint(cert)
    return thumbrint
}

fun getThumbprint(cert: Certificate): String {
    val md = MessageDigest.getInstance("SHA-1")
    val der: ByteArray = cert.encoded
    md.update(der)
    val digest = md.digest()
    val digestHex = DatatypeConverter.printHexBinary(digest)
    return digestHex.lowercase(Locale.getDefault())
}