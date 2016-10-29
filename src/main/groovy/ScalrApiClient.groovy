import groovy.json.JsonBuilder
import groovy.json.JsonSlurper
import org.apache.http.HttpEntity
import org.apache.http.client.methods.CloseableHttpResponse
import org.apache.http.client.methods.HttpGet
import org.apache.http.client.methods.HttpPost
import org.apache.http.client.methods.HttpPut
import org.apache.http.client.methods.HttpUriRequest
import org.apache.http.conn.ssl.NoopHostnameVerifier
import org.apache.http.conn.ssl.SSLConnectionSocketFactory
import org.apache.http.conn.ssl.TrustSelfSignedStrategy
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClients
import org.apache.http.ssl.SSLContextBuilder
import org.apache.http.util.EntityUtils

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.text.SimpleDateFormat

public class ScalrApiClient {
    private final static String CRYPTO_ALGO = "HmacSHA256"
    private static final String API_KEY_ID_HEADER = "X-Scalr-Key-Id"
    private static final String SIGNATURE_HEADER = "X-Scalr-Signature"
    private static final String DATE_HEADER = "X-Scalr-Date"
    private static final String DEBUG_HEADER = "X-Scalr-Debug"
    private static final String DEBUG_ENABLED_HEADER_VALUE = "1"
    private static final String SIGNATURE_HEADER_VALUE_PREFIX = "V1-HMAC-SHA256"
    private static final String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'"
    private static final String UTC = "UTC"

    private final String scalrBaseUrl
    private final String apiKeyId
    private final String apiSecret
    private final SimpleDateFormat sdf
    private final CloseableHttpClient httpClient
    private final Mac mac
    private final Boolean debugMode
    private final Boolean strictSsl

    public ScalrApiClient(scalrBaseUrl, apiKeyId, apiSecret, strictSsl = true, debugMode = false) {
        this.scalrBaseUrl = scalrBaseUrl
        this.apiKeyId = apiKeyId
        this.apiSecret = apiSecret
        this.strictSsl = strictSsl
        this.debugMode = debugMode
        this.sdf = buildDateFormatter()
        this.httpClient = buildSecureHttpClient()
        this.mac = buildMac()
    }

    private Mac buildMac() {
        Mac mac = Mac.getInstance(CRYPTO_ALGO)
        SecretKeySpec secretKeySpec = new SecretKeySpec(apiSecret.getBytes(), CRYPTO_ALGO)
        mac.init(secretKeySpec)
        mac
    }

    private SimpleDateFormat buildDateFormatter() {
        SimpleDateFormat result = new SimpleDateFormat(DATE_FORMAT)
        result.setTimeZone(TimeZone.getTimeZone(UTC));
        result
    }

    private CloseableHttpClient buildSecureHttpClient() {
        CloseableHttpClient result
        if (strictSsl) {
            result = HttpClients.createDefault()
        } else {
            SSLContextBuilder builder = new SSLContextBuilder();
            builder.loadTrustMaterial(null, new TrustSelfSignedStrategy());
            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(builder.build(), new NoopHostnameVerifier());
            result = HttpClients.custom().setSSLSocketFactory(sslsf).build()
        }
        result
    }

    public String execute(String httpMethod, String path, String parameters = "", String body = "") {
        String result = null
        HttpUriRequest request = buildRequest(httpMethod, path, parameters, body)
        CloseableHttpResponse response = httpClient.execute(request);
        try {
            println response.getStatusLine()
            HttpEntity entity = response.getEntity()
            result = new JsonBuilder(new JsonSlurper().parse(entity.getContent())).toPrettyString()
            EntityUtils.consume(entity)
        } finally {
            response.close()
        }
        return result
    }

    private HttpUriRequest buildRequest(String httpMethod, String path, String parameters, String body) {
        HttpUriRequest result
        String dateString = sdf.format(new Date())
        String canonicalRequest = buildCanonicalRequest(httpMethod, dateString, path, parameters, body)

        switch (httpMethod) {
            case HttpGet.METHOD_NAME:
                result = new HttpGet(this.scalrBaseUrl + path)
                break
            case HttpPost.METHOD_NAME:
                result = new HttpPost(this.scalrBaseUrl + path)
                break
            case HttpPut.METHOD_NAME:
                result = new HttpPut(this.scalrBaseUrl + path)
                break
            default:
                throw new RuntimeException("Unsupported Http method: $httpMethod")
        }
        result.addHeader(API_KEY_ID_HEADER, apiKeyId)
        result.addHeader(SIGNATURE_HEADER, "$SIGNATURE_HEADER_VALUE_PREFIX ${buildSignature(canonicalRequest)}")
        result.addHeader(DATE_HEADER, dateString)
        if (debugMode) result.addHeader(DEBUG_HEADER, DEBUG_ENABLED_HEADER_VALUE)
        result
    }

    private String buildSignature(String canonicalRequest) {
        byte[] digest = mac.doFinal(canonicalRequest.getBytes())
        String signature = digest.encodeBase64().toString()
        println "signature: $signature"
        signature
    }

    private String buildCanonicalQueryString(String parameters) {
        //TODO
        ""
    }

    private String buildCanonicalRequest(String httpMethod, String dateString, String path, String parameters, String body) {
        "$httpMethod\n$dateString\n${path}\n${buildCanonicalQueryString(parameters)}\n$body"
    }
}
