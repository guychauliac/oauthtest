package chabernac.oauth.authtest;

import com.github.scribejava.core.builder.api.DefaultApi20;

public class Auth0Api extends DefaultApi20 {

    @Override
    public String getAccessTokenEndpoint() {
        return "https://dev-chabernac.eu.auth0.com/oauth/token";
    }

    @Override
    protected String getAuthorizationBaseUrl() {
        return "https://dev-chabernac.eu.auth0.com/";
    }

    @Override
    public String getResourceUrl() {
        return "https://dev-chabernac.eu.auth0.com/api/v2/";
    }

}
