// Copyright (c) 2021 Cisco Systems, Inc and its affiliates
// All Rights reserved
package main

import (
	"fmt"
	"github.com/CiscoDevNet/go-msx-swagger"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

func hello(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello from myservice! Your token is: "+r.Header.Get("Authorization"))
}

func main() {
	c := msxswagger.NewDefaultMsxSwaggerConfig()
	// Set security to disable MSX authentication.
	c.DocumentationConfig.Security.Enabled = false
	// Set the path to your pre-generated swagger specification in json format
	c.SwaggerJsonPath = "swagger.json.2"
	// This example has an older 2.0 spec so we'll configure that as well to demonstrate.
	c.DocumentationConfig.SpecVersion = "2.0"
	// Set the root path for my app would default to / if not explicitly set.
	c.DocumentationConfig.RootPath = "/myservice"
	s, err := msxswagger.NewMsxSwagger(c)
	if err != nil {
		log.Fatal(err)
	}
	r := mux.NewRouter()
	// SwaggerRoutes requires a wildcard on the prefix as it serves multiple routes.
	// In this example we are using gorilla/mux with PathPrefix to match everything.
	r.PathPrefix("/myservice/swagger").HandlerFunc(s.SwaggerRoutes)
	// Add a route to my hello function.
	r.Path("/myservice/api/v1/hello").HandlerFunc(hello)
	http.ListenAndServe(":8080", r)
}
