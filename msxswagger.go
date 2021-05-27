//
// Copyright (c) 2021 Cisco Systems, Inc and its affiliates
// All Rights reserved
//
package msxswagger

import (
	"encoding/json"
	"fmt"
	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi2conv"
	"github.com/getkin/kin-openapi/openapi3"
	"io/ioutil"
	"log"
	"net/http"
)

// MsxSwagger contains all required information to serve a swagger page
// config is a pointer to a MsxSwaggerConfig
// spec is an openapi Swagger spec
// fileSystem is an http fileSystem
type MsxSwagger struct {
	config     *MsxSwaggerConfig
	spec       *openapi3.Swagger
	fileSystem http.FileSystem
}

// NewMsxSwagger take a MsxSwaggerConfig and returns a MsxSwagger Object
// Will return an error if provided swagger.json file is not parsable
func NewMsxSwagger(cfg *MsxSwaggerConfig) (*MsxSwagger, error) {
	var f http.FileSystem
	var err error
	if cfg.DocumentationConfig.Security.Enabled {
		log.Print("Loading Secure FS")
		f, err = getauthfs()
		if err != nil {
			log.Printf("Error loading FS: %s", err.Error())
		}
	} else {
		log.Print("Loading noauth FS")
		f, err = getnoauthfs()
		if err != nil {
			log.Printf("Error loading FS: %s", err.Error())
		}
	}
	var s *openapi3.Swagger

	if cfg.DocumentationConfig.SpecVersion == "2.0" {
		sjson, err := ioutil.ReadFile(cfg.SwaggerJsonPath)
		if err != nil {
			log.Printf("Error reading swagger json file: %s", err.Error())
			return nil, err
		}
		var swag openapi2.Swagger
		err = json.Unmarshal(sjson, &swag)
		if err != nil {
			log.Printf("Error decoding swagger json file: %s", err.Error())
			return nil, err
		}
		s, err = openapi2conv.ToV3Swagger(&swag)
		if err != nil {
			log.Printf("Error converting swagger json file to v3: %s", err.Error())
			return nil, err
		}
		return &MsxSwagger{
			config:     cfg,
			fileSystem: f,
			spec:       s,
		}, nil
	}
	s, err = openapi3.NewSwaggerLoader().LoadSwaggerFromFile(cfg.SwaggerJsonPath)
	if err != nil {
		log.Printf("Error reading swagger json file: %s", err.Error())
		return nil, err
	}
	return &MsxSwagger{
		config:     cfg,
		fileSystem: f,
		spec:       s,
	}, nil

}

func (p *MsxSwagger) getSpec(w http.ResponseWriter, r *http.Request) {
	resp, err := p.spec.MarshalJSON()
	if err != nil {
		p.errorHandler(w, r)
	}
	w.Header().Set("content-type", "application/json")
	fmt.Fprintf(w, string(resp))
}

func (p *MsxSwagger) getSsoSecurity(w http.ResponseWriter, r *http.Request) {
	sso := p.config.DocumentationConfig.Security.Sso
	resp, err := json.Marshal(struct {
		AuthorizeUrl string `json:"authorizeUrl"`
		ClientId     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		TokenUrl     string `json:"tokenUrl"`
	}{
		AuthorizeUrl: sso.BaseUrl + sso.AuthorizePath,
		ClientId:     sso.ClientId,
		ClientSecret: sso.ClientSecret,
		TokenUrl:     sso.BaseUrl + sso.TokenPath,
	})
	if err != nil {
		p.errorHandler(w, r)
	}
	w.Header().Set("content-type", "application/json")
	fmt.Fprintf(w, string(resp))
}

func (p MsxSwagger) getUi(w http.ResponseWriter, r *http.Request) {
	resp, err := json.Marshal(struct {
		ApisSorter               string   `json:"apisSorter"`
		DeepLinking              bool     `json:"deepLinking"`
		DefaultModelExpandDepth  int      `json:"defaultModelExpandDepth"`
		DefaultModelRendering    string   `json:"defaultModelRendering"`
		DefaultModelsExpandDepth int      `json:"defaultModelsExpandDepth"`
		DisplayOperationId       bool     `json:"displayOperationId"`
		DisplayRequestDuration   bool     `json:"displayRequestDuration"`
		DocExpansion             string   `json:"docExpansion"`
		Filter                   bool     `json:"filter"`
		JsonEditor               bool     `json:"jsonEditor"`
		OperationsSorter         string   `json:"operationsSorter"`
		ShowExtensions           bool     `json:"showExtensions"`
		ShowRequestHeaders       bool     `json:"showRequestHeaders"`
		SupportedSubmitMethods   []string `json:"supportedSubmitMethods"`
		TagsSorter               string   `json:"tagsSorter"`
		ValidatorUrl             string   `json:"validatorUrl"`
	}{
		ApisSorter:               "alpha",
		DeepLinking:              true,
		DefaultModelExpandDepth:  1,
		DefaultModelRendering:    "example",
		DefaultModelsExpandDepth: 1,
		DisplayOperationId:       false,
		DisplayRequestDuration:   false,
		DocExpansion:             "none",
		Filter:                   false,
		JsonEditor:               false,
		OperationsSorter:         "alpha",
		ShowExtensions:           false,
		ShowRequestHeaders:       false,
		SupportedSubmitMethods:   []string{"get", "post", "put", "delete", "patch", "head", "options", "trace"},
		TagsSorter:               "alpha",
		ValidatorUrl:             "",
	})
	if err != nil {
		p.errorHandler(w, r)
	}
	w.Header().Set("content-type", "application/json")
	fmt.Fprintf(w, string(resp))
}

func (p *MsxSwagger) getSwaggerResources(w http.ResponseWriter, r *http.Request) {
	resp, err := json.Marshal(
		[]struct {
			Name           string `json:"name"`
			Location       string `json:"location"`
			Url            string `json:"url"`
			SwaggerVersion string `json:"swaggerVersion"`
		}{
			{
				Name:           "platform",
				Location:       p.config.DocumentationConfig.SwaggerPath + p.config.DocumentationConfig.ApiPath,
				Url:            p.config.DocumentationConfig.SwaggerPath + p.config.DocumentationConfig.ApiPath,
				SwaggerVersion: "2.0",
			},
		})
	if err != nil {
		p.errorHandler(w, r)
	}
	w.Header().Set("content-type", "application/json")
	fmt.Fprintf(w, string(resp))
}

func (p *MsxSwagger) errorHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "text/plain")
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, "Internal Server Error")
}

func (p *MsxSwagger) getSecurity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	fmt.Fprintf(w, "{}")
}

//SwaggerRoutes is an http.Handlefunc that serves MsxSwagger
//As this function must handle multiple paths it must be served from a handler that supports wildcard paths
//mount path must match values configured in MsxSwagger config RootPath + UI.Endpoint
func (p *MsxSwagger) SwaggerRoutes(w http.ResponseWriter, r *http.Request) {
	url := r.RequestURI
	switch {
	case url == p.config.DocumentationConfig.RootPath+p.config.DocumentationConfig.Ui.Endpoint + "/":
		http.Redirect(w,r,p.config.DocumentationConfig.RootPath+p.config.DocumentationConfig.Ui.Endpoint,http.StatusPermanentRedirect)
	case url == p.config.DocumentationConfig.RootPath+p.config.DocumentationConfig.Ui.Endpoint+p.config.DocumentationConfig.SwaggerPath:
		p.getSwaggerResources(w, r)
	case url == p.config.DocumentationConfig.RootPath+p.config.DocumentationConfig.Ui.Endpoint+p.config.DocumentationConfig.SwaggerPath+"/configuration/security/sso":
		p.getSsoSecurity(w, r)
	case url == p.config.DocumentationConfig.RootPath+p.config.DocumentationConfig.Ui.Endpoint+p.config.DocumentationConfig.SwaggerPath+"/configuration/ui":
		p.getUi(w, r)
	case url == p.config.DocumentationConfig.RootPath+p.config.DocumentationConfig.Ui.Endpoint+p.config.DocumentationConfig.SwaggerPath+p.config.DocumentationConfig.ApiPath:
		p.getSpec(w, r)
	case url == p.config.DocumentationConfig.RootPath+p.config.DocumentationConfig.Ui.Endpoint+p.config.DocumentationConfig.SwaggerPath+"/configuration/security":
		p.getSecurity(w, r)
	default:
		http.StripPrefix(p.config.DocumentationConfig.RootPath+p.config.DocumentationConfig.Ui.Endpoint, http.FileServer(p.fileSystem)).ServeHTTP(w, r)

	}
}
