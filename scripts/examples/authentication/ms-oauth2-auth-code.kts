import com.stackhawk.zap.extension.talon.hawkscan.ExtensionTalonHawkscan
import io.netty.handler.codec.http.QueryStringDecoder
import org.apache.commons.httpclient.URI
import org.apache.log4j.LogManager
import org.openqa.selenium.By
import org.openqa.selenium.Cookie
import org.openqa.selenium.WebDriver
import org.openqa.selenium.chrome.ChromeDriver
import org.openqa.selenium.chrome.ChromeOptions
import org.openqa.selenium.firefox.FirefoxDriver
import org.openqa.selenium.firefox.FirefoxOptions
import org.openqa.selenium.support.ui.ExpectedConditions
import org.openqa.selenium.support.ui.WebDriverWait
import org.parosproxy.paros.control.Control
import org.parosproxy.paros.network.HttpHeader
import org.parosproxy.paros.network.HttpMessage
import org.parosproxy.paros.network.HttpRequestHeader
import com.stackhawk.hste.authentication.AuthenticationHelper
import com.stackhawk.hste.authentication.GenericAuthenticationCredentials
import java.net.URLEncoder
import java.time.Duration


val logger = LogManager.getLogger("ms-oauth2-auth-code")
var webDriver : WebDriver? = null
var cookies : MutableSet<Cookie>? = null

fun getLoggedOutIndicator() : String {
    return "HTTP/\\d+\\.\\d+\\s+(2[0-9][0-9]|3[0-9][0-9])"
}

fun getLoggedInIndicator() : String {
    return "HTTP/\\d+\\.\\d+\\s+(4[0-9][0-9])"
}


// Convenience Methods for setting up drivers
fun setUpChromeDriver(headless : Boolean) {
    val options = ChromeOptions()
    if (headless) {
        options.addArguments("--headless=new")
    }
    webDriver = ChromeDriver(options)
}

fun setupFirefoxDriver(headless : Boolean) {
    webDriver = FirefoxDriver(FirefoxOptions().setHeadless(headless))
}

fun initializeDriver() {
    val talon = Control
        .getSingleton()
        .extensionLoader
        .getExtension(ExtensionTalonHawkscan::class.java)

    when(talon.talonHawkScanConf.hawkscanConf.hawk.spider.ajaxBrowser.name) {
        "CHROME"-> setUpChromeDriver(false)
        "CHROME_HEADLESS" -> setUpChromeDriver(true)
        "FIREFOX" -> setupFirefoxDriver(false)
        "FIREFOX_HEADLESS" -> setupFirefoxDriver(true)
        else -> throw(Exception("Please specify browser type in the ajax spider config"))
    }

}

fun tearDown() {
    webDriver?.quit()
}

// Convenience Selenium Methods
fun clickButtonById(id : String) {
    val button = webDriver?.findElement(By.id(id))
    button?.click()
}

fun clickButtonByName(name : String) {
    val button = webDriver?.findElement(By.name(name))
    button?.click()
}

fun clickButtonByClass(name : String) {
    val button = webDriver?.findElement(By.className(name))
    button?.click()
}

fun enterText(id : String, text : String) {
    val field = webDriver?.findElement(By.id(id))
    field?.sendKeys(text)
}

fun enterTextByName(id : String, text : String) {
    val field = webDriver?.findElement(By.name(id))
    field?.sendKeys(text)
}

fun waitForElement(name: String) {
    val wait = WebDriverWait(webDriver, 20)
    wait.until(ExpectedConditions.elementToBeClickable(By.name(name)));
}

fun waitForElementClassName(name: String) {
    val wait = WebDriverWait(webDriver, 20)
    wait.until(ExpectedConditions.elementToBeClickable(By.className(name)));
}

fun seleniumWait(timeInSecs : Long = 5) {
    val wait = WebDriverWait(webDriver, timeInSecs)
    wait.withTimeout(Duration.ofSeconds(timeInSecs))
}

fun getQueryParam(name : String) : String? {
    val url = webDriver?.currentUrl
    logger.info("here is the current url $url")
    try {
        val query = QueryStringDecoder(java.net.URI(url))
        return query.parameters()[name]?.first()
    } catch (ex : Exception) {
        logger.error(ex.message, ex)
    }

    return ""
}


// This function is called before a scan is started and when the loggedOutIndicator is matched indicating re-authentication is needed.
fun authenticate(
    helper: AuthenticationHelper,
    paramsValues: Map<String, String>,
    credentials: GenericAuthenticationCredentials
): HttpMessage {

    logger.info("Setting up web driver")
    initializeDriver()

    logger.info("getting login page")
    val username = credentials.getParam("username")
    val password = credentials.getParam("password")
    val clientId = credentials.getParam("client_id")
    val redirectURL =  URLEncoder.encode(credentials.getParam("redirect_url"), "UTF-8")
    val responseType =  paramsValues["response_type"]
    val responseMode =  paramsValues["response_mode"]
    val scope =  URLEncoder.encode(paramsValues["scope"], "UTF-8")
    val loginPath = paramsValues["loginPath"]
    val loggedInPath = "$loginPath?client_id=$clientId&response_type=$responseType&redirect_uri=$redirectURL&scope=$scope&response_mode=$responseMode&state=12345&nonce=678910"

    webDriver?.get(loggedInPath)
    logger.info("Current Url {${webDriver?.currentUrl}")

    // Wait for username field to appear
    waitForElement("loginfmt")
    logger.info("Entering username")
    enterTextByName("loginfmt", username)


    logger.info("Clicking the login button")
    clickButtonByClass("button_primary")

    // Wait for passsword field
    waitForElement("passwd")
    logger.info("Entering password")
    enterTextByName("passwd", password)

    logger.info("Clicking the login button")
    clickButtonByClass("button_primary")

    // Wait for keep me signed in button
    waitForElementClassName("button_primary")
    logger.info("Clicking the sgined in button button")
    clickButtonByClass("button_primary")

    logger.info("waiting")
    // Nothing element to wait for yet, so just wait 5 seconds
    // Can be replaced by wiathForElement of your choosing
    seleniumWait()

    // Get the code from the url
    val code = getQueryParam("code")

    logger.info("here is the $code")
    val tokenRequestUrl =  paramsValues["token_request"]
    val tokenRequestScope =  paramsValues["token_request_scope"]
    val tokenRequestGrant =  paramsValues["token_request_grant"]
    val clientSecret = credentials.getParam("client_secret")

    logger.info("Here is the token request $tokenRequestUrl")

    // Create the request to get an access token
    var tokenRequest = URI(tokenRequestUrl, false);
    logger.info("Here is the token request $tokenRequest")
    var tokenRequestHeader = HttpRequestHeader(HttpRequestHeader.POST, tokenRequest, HttpHeader.HTTP11)

    var tokenMsg = helper.prepareMessage()

    // Set body params
    var requestBody = "scope="+ tokenRequestScope +
            "&redirect_uri=" + redirectURL +
            "&grant_type=" +tokenRequestGrant +
            "&client_id=" +clientId +
            "&client_secret=" +clientSecret +
            "&code=" + code;

    tokenMsg.setRequestBody(requestBody)
    tokenRequestHeader.contentLength = tokenMsg.requestBody.length();
    tokenRequestHeader.setHeader("Content-Type", "application/x-www-form-urlencoded");
    tokenRequestHeader.setHeader("Accept", "application/json");
    tokenRequestHeader.setHeader("Cache-control", "no-cache");


    logger.info("Here is the request body ${tokenMsg.requestBody}")


    tokenMsg.requestHeader = tokenRequestHeader

    logger.info("Here is the request headder ${tokenMsg.requestHeader}")

    helper.sendAndReceive(tokenMsg)

    logger.info("Response body ${tokenMsg.responseBody}")
    logger.info("Response header ${tokenMsg.responseHeader}")

    tearDown()

    return tokenMsg
}

// The required parameter names for your script, your script will throw an error if these are not supplied in the script.parameters configuration.
fun getRequiredParamsNames(): Array<String> {
    return arrayOf("loginPath", "response_type", "scope", "response_mode", "token_request", "token_request_scope", "token_request_grant")
}

// The required credential parameters, your script will throw an error if these are not supplied in the script.credentials configuration.
fun getCredentialsParamsNames(): Array<String> {
    return arrayOf("username", "password","client_id", "redirect_url", "client_secret")
}

fun getOptionalParamsNames(): Array<String> {
    return emptyArray()
}