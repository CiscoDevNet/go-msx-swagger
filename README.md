# MSX Swagger
https://github.com/CiscoDevNet/go-msx-swagger

Package `CiscoDevNet/go-msx-swagger` adds a Swagger interface to your MSX service. The main features are:
* expose a Swagger interface for your MSX service
* optionally secure access with MSX User Management Service integration
* supports OpenAPI 2.0 and 3.0 specifications 

---

* [Install](#install)
* [Usage](#usage)
* [Public SSO Security Clients](#public-sso-security-clients)
* [Unsecured Example](#unsecured-example)
* [Secured Example](#secured-example)
* [License](#license)



## Install
With a correctly configured Go toolchain:
```shell 
go get -u github.com/CiscoDevNet/go-msx-swagger
```


## Usage
Using `go-msx-swagger` is simple:
1. Generate an OpenAPI specification for your service and save the resulting json to a file
that can be accessed by your application. The default OpenAPI version is 3.0, but it can be controlled through configuration.

2. Import the package into your app.

3. Configure it and add a wild card route to your configured endpoint.


## Public SSO Security Clients
Before you can secure your MSX Swagger documentation with `msxswagger` you will need to create a public SSO security client. First sign in to your MSX environment then either:
* open `Settings->SSO Configurations->Add SSO Clients` and add a new client, or 
* use the MSX Swagger documentation for `IDM Microservice->Security Clients->POST /idm/api/v2/clientsecurity`. 

This example payload is a good starting point, but be sure to change it meet your specific requirements.
```json
{
    "clientId":"my-public-client",
    "grantTypes":[
        "refresh_token",
        "authorization_code"
    ],
    "maxTokensPerUser":-1,
    "useSessionTimeout":false,
    "resourceIds":[
    ],
    "scopes":[
        "address",
        "read",
        "phone",
        "openid",
        "profile",
        "write",
        "email"
    ],
    "autoApproveScopes":[
        "address",
        "read",
        "phone",
        "openid",
        "profile",
        "write",
        "email"
    ],
    "authorities":[
        "ROLE_USER",
        "ROLE_PUBLIC"
    ],
    "registeredRedirectUris":[
        "/**/swagger-sso-redirect.html"
    ],
    "accessTokenValiditySeconds":9000,
    "refreshTokenValiditySeconds":18000,
    "additionalInformation":{
    }
}
```

## Unsecured Example
To add unsecured Swagger documentation create an OpenAPI 3.0 specification called `swagger.json` and save it to the same folder as your service binary. This Swagger documentation will be visible to anyone that can reach your MSX environment, even if they do not have user credentials.
```go
// Create a new default msxswagger configuration.
c := msxswagger.NewDefaultSwaggerConfig()
// Disable security.
c.DocumentationConfig.Security.Enabled = false
// Configure the path to your specification file.
c.SwaggerJsonPath = "swagger.json"
// Configure the base context for your web application.
c.DocumentationConfig.RootPath = "/myservice"
// Create a new instance of msxswagger
s, _ := msxswagger.NewSwagger(c)
// Add it to your router as a wildcard path match to your configured Swagger 
// path (defaults to /swagger). In this example we are using a gorilla/mux router.
r.PathPrefix("/myservice/swagger").HandlerFunc(s.SwaggerRoutes)
```

To use an older 2.0 spec simply add the following:
```go
c.DocumentationConfig.SpecVersion = "2.0"
```

## Secured Example
To secure your Swagger documentation using the MSX User Management Service configure `msxswagger` as shown. Users will then need to sign in to MSX to access Swagger.
```go
// Create a new default msxswagger configuration.
c := msxswagger.NewDefaultSwaggerConfig()
// Enable security.
c.DocumentationConfig.Security.Enabled = true
// Configure the path to your MSX User Management Service. Your application must
// be served from the same FQDN or MSX will reject the OAuth redirect.
c.DocumentationConfig.Security.Sso.BaseUrl = "https://trn6-demo2.ciscovms.com/idm"
// Configure the path to your specification file.
c.SwaggerJsonPath = "swagger.json"
// Configure the base context for your web application.
c.DocumentationConfig.RootPath = "/myservice"
// Create a new instance of msxswagger.
s, _ := msxswagger.NewSwagger(c)
// Add it to your router as a wildcard path match to your configured Swagger 
// path (defaults to /swagger). In this example we are using a gorilla/mux router.
r.PathPrefix("/myservice/swagger").HandlerFunc(s.SwaggerRoutes)
```

Once your app has started you can see your Swagger UI by going to the configured route. In a production solution you might want to pull dynamic configuration values from Vault or Consul.

Checkout the example directory for a simple working example.


## License
MIT licensed. See the LICENSE file for details.
