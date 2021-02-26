//
// Copyright (c) 2021 Cisco Systems, Inc and its affiliates
// All Rights reserved
//
package msxswagger

//MsxSwaggerConfig represents a MsxSwagger config object
//SwaggerJsonPath is the path to your openapi json file.
type MsxSwaggerConfig struct {
	SwaggerJsonPath     string
	AppInfo             AppInfo
	DocumentationConfig DocumentationConfig
}

//AppInfo describes the application
type AppInfo struct {
	Name        string
	Description string
	Version     string
}

//DocumentationConfig is the config used to configure your swagger
//Key config elements are:
//RootPath is the base path your application is serving from defaults to /
//UI.Endpoint is the path you are serving swagger from defaults to /swagger and is
//concatinated with RootPath when accessing from the browser
//Security.Enabled flags Oauth on or off
//Security.Sso.BaseUrl is the path to MSX Usermanagment Service should be changed
type DocumentationConfig struct {
	RootPath    string
	ApiPath     string `config:"default=/apidocs.json"`
	SwaggerPath string `config:"default=/swagger-resources"`
	SpecVersion string `config:"default=3.0.0"`
	Security    Security
	Ui          struct {
		Endpoint string `config:"default=/swagger"`
		View     string `config:"default=/swagger-ui.html"`
	}
}

type Security struct {
	Enabled bool
	Sso     Sso
}

type Sso struct {
	BaseUrl       string `config:"default=http://localhost:9103/idm"`
	TokenPath     string `config:"default=/v2/token"`
	AuthorizePath string `config:"default=/v2/authorize"`
	ClientId      string `config:"default="`
	ClientSecret  string `config:"default="`
}

func NewDefaultMsxSwaggerConfig() *MsxSwaggerConfig {
	sso := Sso{
		BaseUrl:       "https://localhost:9103/idm",
		TokenPath:     "/v2/token",
		AuthorizePath: "/v2/authorize",
		ClientId:      "",
		ClientSecret:  ""}

	dc := DocumentationConfig{
		RootPath:    "/",
		ApiPath:     "/apidocs.json",
		SwaggerPath: "/swagger-resources",
		SpecVersion: "3.0.0",
		Ui: struct {
			Endpoint string `config:"default=/swagger"`
			View     string `config:"default=/swagger-ui.html"`
		}{
			Endpoint: "/swagger",
			View:     "/swagger-ui.html",
		},
		Security: Security{false, sso},
	}

	return &MsxSwaggerConfig{
		SwaggerJsonPath:     "swagger.json",
		DocumentationConfig: dc,
	}

}
