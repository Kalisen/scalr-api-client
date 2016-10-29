import org.apache.http.client.methods.HttpGet


Properties props = new Properties()
props.load(this.class.getResourceAsStream("scalr.properties"))
def scalr = new ScalrApiClient(
        props.getProperty("scalr.base.url"),
        props.getProperty("apiKeyId"),
        props.getProperty("apiSecret"),
        Boolean.valueOf(props.getProperty("strictSsl")),
        Boolean.valueOf(props.getProperty("debugMode"))
)

final int DEFAULT_ENV_ID = 4
final int farmRoleId = 100
println scalr.execute(HttpGet.METHOD_NAME, "/api/v1beta0/user/$DEFAULT_ENV_ID/farm-roles/$farmRoleId")

