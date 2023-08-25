// Copyright (c) 2021 Cisco Systems, Inc and its affiliates
// All Rights reserved
package msxswagger

// MsxSwaggerConfig represents a MsxSwagger config object
// SwaggerJsonPath is the path to your openapi json file.
type MsxSwaggerConfig struct {
	SwaggerJsonPath     string
	AppInfo             AppInfo
	DocumentationConfig DocumentationConfig
}

// AppInfo describes the application
type AppInfo struct {
	Name        string
	Description string
	Version     string
}

// DocumentationConfig is the config used to configure your swagger
// Key config elements are:
// RootPath is the base path your application is serving from defaults to /
// Security.Enabled flags Oauth on or off
// Security.Sso.BaseUrl is the path to MSX Usermanagment Service should be changed
type DocumentationConfig struct {
	RootPath    string
	ApiPath     string `config:"default=/apidocs.json"`
	SpecVersion string `config:"default=3.0.0"`
	Security    Security
	Title       string
}

type Security struct {
	Enabled bool
	Sso     Sso
}

type ParamMeta struct {
	Name               string
	DisplayName        string
	CandidateSourceUrl string
	CandidateJsonPath  string
}

type Sso struct {
	BaseUrl              string `config:"default=http://localhost:9103/idm"`
	TokenPath            string `config:"default=/v2/token"`
	AuthorizePath        string `config:"default=/v2/authorize"`
	ClientId             string `config:"default="`
	ClientSecret         string `config:"default="`
	AdditionalParameters []ParamMeta
}

func NewDefaultMsxSwaggerConfig() *MsxSwaggerConfig {
	sso := Sso{
		BaseUrl:       "http://localhost:8900/auth",
		TokenPath:     "/v2/token",
		AuthorizePath: "/v2/authorize",
		ClientId:      "",
		ClientSecret:  ""}

	dc := DocumentationConfig{
		RootPath:    "/",
		ApiPath:     "/apidocs.json",
		SpecVersion: "3.0.0",
		Security:    Security{false, sso},
	}

	return &MsxSwaggerConfig{
		SwaggerJsonPath:     "swagger.json",
		DocumentationConfig: dc,
	}

}
