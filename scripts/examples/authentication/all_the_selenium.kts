import com.stackhawk.zap.extension.talon.hawkscan.ExtensionTalonHawkscan
import io.netty.handler.codec.http.QueryStringDecoder
import org.apache.commons.httpclient.URI
import org.apache.log4j.LogManager
import org.openqa.selenium.By
import org.openqa.selenium.Cookie
import org.openqa.selenium.JavascriptExecutor
import org.openqa.selenium.WebDriver
import org.openqa.selenium.WebElement
import org.openqa.selenium.chrome.ChromeDriver
import org.openqa.selenium.chrome.ChromeOptions
import org.openqa.selenium.firefox.FirefoxDriver
import org.openqa.selenium.firefox.FirefoxOptions
import org.openqa.selenium.firefox.FirefoxProfile
import org.openqa.selenium.support.ui.ExpectedConditions
import org.openqa.selenium.support.ui.WebDriverWait
import org.parosproxy.paros.control.Control
import org.parosproxy.paros.network.HttpHeader
import org.parosproxy.paros.network.HttpMessage
import org.parosproxy.paros.network.HttpRequestHeader
import org.zaproxy.zap.authentication.AuthenticationHelper
import org.zaproxy.zap.authentication.GenericAuthenticationCredentials
import java.net.HttpCookie
import java.time.Duration


val logger = LogManager.getLogger("Selenium Auth GO!")
var webDriver : WebDriver? = null

fun getLoggedOutIndicator() : String {
    return "$^"
}

fun getLoggedInIndicator() : String {
    return ".*"
}


// Convenience Methods for setting up drivers
fun setUpChromeDriver(headless : Boolean) {
    // May need to download a newer verison of chrome driver and the set the path to you where you unzip it https://googlechromelabs.github.io/chrome-for-testing/
    // System.setProperty("webdriver.chrome.driver", "/path/to/chromedriver")
    val options = ChromeOptions()
    if (headless) {
        options.addArguments("--headless=new")
    }
    webDriver = ChromeDriver(options)
}

fun setupFirefoxDriver(headless : Boolean) {
    val options = FirefoxOptions()
    val profile = FirefoxProfile()
    profile.setPreference("general.useragent.override", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.90 Safari/537.36")
    options.setProfile(profile)

    if (headless) {
        options.addArguments("-headless")
    }
    webDriver = FirefoxDriver(options)
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
fun clickButton(id : String) {
    val button = webDriver?.findBy(id, Descriptor.ID)
    button?.click()
}

fun clickButtonByName(name : String) {
    val button = webDriver?.findBy(name, Descriptor.NAME)
    button?.click()
}

fun clickButtonByClass(name : String) {
    val button = webDriver?.findBy(name, Descriptor.CLASSNAME)
    button?.click()
}

fun enterText(id : String, text : String) {
    val field = webDriver?.findBy(id, Descriptor.ID)
    field?.sendKeys(text)
}

fun enterTextByName(id : String, text : String) {
    val field = webDriver?.findBy(id, Descriptor.NAME)
    field?.sendKeys(text)
}

fun waitForElementByName(name: String) {
    val wait = WebDriverWait(webDriver, Duration.ofSeconds(20))
    wait.until(ExpectedConditions.elementToBeClickable(By.name(name)));
}

fun waitForElementClassName(name: String, timeOut : Long = 20) {
    webDriver?.wait(timeOut)?.until(ExpectedConditions.elementToBeClickable(By.className(name)));
}

fun waitForElement(id : String, timeOut : Long = 20) {
    webDriver?.wait(timeOut)?.until(ExpectedConditions.elementToBeClickable(By.id(id)));
}

fun waitForClicakbleElement(element : WebElement, timeOut : Long = 20) {
    webDriver?.wait(timeOut)?.until(ExpectedConditions.elementToBeClickable(element))
}

fun seleniumWait(timeInSecs : Long = 5) {
    webDriver?.manage()?.timeouts()?.implicitlyWait(Duration.ofSeconds(timeInSecs))
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

fun getCookies() : MutableSet<Cookie>? {
    return webDriver?.manage()?.cookies
}

fun getCookie(name: String) : Cookie? {
    return webDriver?.manage()?.getCookieNamed(name)
}

fun elements() {

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
    val loginPath = paramsValues["loginURI"]
    val usernameField = paramsValues["usernameField"] ?: "username"
    val passwordField = paramsValues["passwordField"] ?: "password"
    val loginButton = paramsValues["loginButton"] ?: "logIn"
    val localStorage = paramsValues["localStorage"] ?: "token"
    val loggedInIndicator = paramsValues["loggedInIndicator"] ?: "logOut"

    logger.info("Here ist he login path $loginPath")

    webDriver?.get(loginPath)
    logger.info("Current Url ${webDriver?.currentUrl}")

    // Wait for username field to appear
    waitForElement(usernameField)
    logger.info("Entering username")
    enterText(usernameField, username)


    // Wait for passsword field
    // waitForElement("passwordField")
    logger.info("Entering password")
    enterText(passwordField, password)

    logger.info("Clicking the login button")
    clickButton(loginButton)


    logger.info("waiting")
    // Nothing element to wait for yet, so just wait 5 seconds
    // Can be replaced by wiathForElement of your choosing
    waitForElement(loggedInIndicator)
    // seleniumWait(60)
    while(webDriver?.currentUrl?.contains("api") == true) {
        when(webDriver?.currentUrl?.split("/")?.last()) {
            "login" -> {  //  Do something
            }
             else -> break
        }
    }

    seleniumWait(20)


    // Create the request to get an access token
    var tokenRequest = URI("https://localhost:9000", false);
    logger.info("Here is the token request $tokenRequest")
    var tokenRequestHeader = HttpRequestHeader(HttpRequestHeader.GET, tokenRequest, HttpHeader.HTTP11)

    var tokenMsg = helper.prepareMessage()


    logger.info("Here is the request body ${tokenMsg.requestBody}")


    tokenMsg.requestHeader = tokenRequestHeader

    logger.info("Here is the request headder ${tokenMsg.requestHeader}")

    // helper.sendAndReceive(tokenMsg)

    logger.info("Response body ${tokenMsg.responseBody}")
    logger.info("Response header ${tokenMsg.responseHeader}")

    val localStorageDriver = LocalStorage(webDriver!!)
    val token = localStorageDriver.getItemFromLocalStorage(localStorage)

    val cookies = getCookies()
    val httpCookies = cookies?.map { val cookie = HttpCookie(it.name, it.value)
        cookie.domain = it.domain
        cookie
    }

    tokenMsg.requestHeader.setCookies(httpCookies)

    tokenMsg.responseBody.content = "{\"token\" : $token}".toByteArray()

    // tearDown()

    return tokenMsg
}

// The required parameter names for your script, your script will throw an error if these are not supplied in the script.parameters configuration.
fun getRequiredParamsNames(): Array<String> {
    return arrayOf("loginURI")
}

// The required credential parameters, your script will throw an error if these are not supplied in the script.credentials configuration.
fun getCredentialsParamsNames(): Array<String> {
    return arrayOf("username", "password")
}

fun getOptionalParamsNames(): Array<String> {
    return arrayOf( "usernameField", "passwordField", "loginButton", "localStorage", "loggedInIndicator")
}
class LocalStorage(webDriver: WebDriver) {
    private val js = webDriver as JavascriptExecutor

    fun removeItemFromLocalStorage(item: String?) {
        js.executeScript(
            String.format(
                "window.localStorage.removeItem('%s');", item
            )
        )
    }

    fun isItemPresentInLocalStorage(item: String?): Boolean {
        return js.executeScript(
            String.format(
                "return window.localStorage.getItem('%s');", item
            )
        ) != null
    }

    fun getItemFromLocalStorage(key: String?): String {
        return js.executeScript(
            String.format(
                "return window.localStorage.getItem('%s');", key
            )
        ) as String
    }

    fun getKeyFromLocalStorage(key: Int): String {
        return js.executeScript(
            String.format(
                "return window.localStorage.key('%s');", key
            )
        ) as String
    }

    val localStorageLength: Long
        get() = js.executeScript("return window.localStorage.length;") as Long

    fun setItemInLocalStorage(item: String?, value: String?) {
        js.executeScript(
            String.format(
                "window.localStorage.setItem('%s','%s');", item, value
            )
        )
    }

    fun clearLocalStorage() {
        js.executeScript(String.format("window.localStorage.clear();"))
    }
}

enum class Descriptor
{
    CLASSNAME,
    ROLE,
    NAME,
    ID,
    PLACEHOLDER
}


fun WebDriver.findBy(id : String, type: Descriptor) : WebElement? {
    return when(type) {
        Descriptor.CLASSNAME -> this.findElement(By.className(id))
        Descriptor.ROLE -> this.findElement(By.cssSelector("[role = '$id']"))
        Descriptor.NAME -> this .findElement(By.name(id))
        Descriptor.ID -> this.findElement(By.id(id))
        Descriptor.PLACEHOLDER -> this.findElement(By.cssSelector("input[placeholder='$id']"))
    }
}

fun WebDriver.wait(seconds: Long) = WebDriverWait(this, Duration.ofSeconds(seconds))