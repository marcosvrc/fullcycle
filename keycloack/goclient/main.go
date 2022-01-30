package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

//Criar/Obter as variáveis abaixo no Keycloak

//1. Criar um client (myclient)
//2. Ajustar o setting do myClient
//myClient -> Aba Settings -> Access Type: Confidential
//3. Aba Credential -> secret

var (
	clientID = "myclient"
	clientSecret = "sYZkNgGcXcNdeSeT7E98DOwnw7RfwMgy"
)

func main () {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, "http://127.0.0.1:8080/auth/realms/myrealm")

	if err != nil {
		log.Fatal(err)
	}

	config := oauth2.Config {
		ClientID: clientID,
		ClientSecret: clientSecret,
		Endpoint: provider.Endpoint(),
		RedirectURL: "http://localhost:8081/auth/callback",
		Scopes: []string{oidc.ScopeOpenID, "profile", "email", "roles"},
	}

	state := "123"


	http.HandleFunc("/", func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, config.AuthCodeURL(state), http.StatusFound) 
	})

	http.HandleFunc("/auth/callback", func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("state") != state {
			http.Error(response, "State Inválido", http.StatusBadRequest)
			return
		}

	token, err := config.Exchange(ctx, request.URL.Query().Get("code"))
		if err != nil {
			http.Error(response,"Falha ao trocar o token", http.StatusInternalServerError)
			return
		}

	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(response,"Falha ao gerar o IdToken", http.StatusInternalServerError)
		return
	}

	userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		http.Error(response,"Erro ao pegar UserInfo", http.StatusInternalServerError)
		return
	}


	resp := struct {
		AccessToken *oauth2.Token
		IDToken string
		UserInfo *oidc.UserInfo
		}{
			token,
			idToken,
			userInfo,
		}

	data, err := json.Marshal(resp)
		if err != nil {
			http.Error(response,err.Error(), http.StatusInternalServerError)
			return
		}
		response.Write(data)

	})

	log.Fatal(http.ListenAndServe(":8081", nil))

}