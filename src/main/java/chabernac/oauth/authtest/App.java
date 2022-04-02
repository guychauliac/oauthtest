package chabernac.oauth.authtest;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.concurrent.ExecutionException;

import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;

/**
 * Hello world!
 */
public class App {
    public static void main( String[] args ) throws IOException, InterruptedException, ExecutionException, SignatureException, ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, IllegalArgumentException, NoSuchAlgorithmException, InvalidKeySpecException, ParseException, BadJOSEException, JOSEException {
        // code executed on client
        OAuth20Service service = new ServiceBuilder( "XtLbfoQxKDQAU1c88vMHCSRUEZ6t01cy" )
            .apiSecret( "vFCROwxrxSlTz8LY92oe5F1ey8QckBW_b3K9gv2zhKyCog2znQKdkfbGPHK0NZvJ" )
            .build( new Auth0Api() );

        String accessToken = service.getAccessTokenClientCredentialsGrant().getAccessToken();
        System.out.println( service.getAccessTokenClientCredentialsGrant().getAccessToken() );
        
        JWTClaimsSet claimSet = validate( accessToken );
        
        System.out.println( claimSet );

//        Jws<Claims> claim = Jwts.parserBuilder()
//            .setSigningKey( getAuth0PublicKey() ) // <---- publicKey, not privateKey
//            .build()
//            .parseClaimsJws( accessToken );

    }

    private static Key getAuth0PublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        // get public keys from https://dev-chabernac.eu.auth0.com/.well-known/jwks.json and find the key mentioned in the
        KeyFactory kFactory = KeyFactory.getInstance( "RSA" );
        // decode base64 of your key
        byte yourKey[] = Base64.getDecoder()
            .decode(
                "MIIDDzCCAfegAwIBAgIJajgyNTCJKtRvMA0GCSqGSIb3DQEBCwUAMCUxIzAhBgNVBAMTGmRldi1jaGFiZXJuYWMuZXUuYXV0aDAuY29tMB4XDTIyMDMyODEzMDczNFoXDTM1MTIwNTEzMDczNFowJTEjMCEGA1UEAxMaZGV2LWNoYWJlcm5hYy5ldS5hdXRoMC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDdsLyb2bcV1DfsvxLmnxjnn0YDMb4i/vfdqSox39zix+yo1rue8eMxQSFg+r3YxFU1HTlLTOlxJCV4VRo4U0ZZHC+o4IUZM7xQUmY429DCK3YCA15Lhk6XZDDpvDbaoHUrCuADZO7cYIoudykcVhHpTp6+QHYEakSOHO6V/oIGZIlt2ajSTUThdT9ZcUMHIZaNBt72yjYCo09ANYh5UcjSz8OGL7Cay8LjLFH0J9Xu97V/Ww8XBbBQvXKe8KPMgAxheBxQjX5hkOIyPZRHkk3EH5u04nQvTMYOrEmM4yNc9CWIYFZyTiazcuJTc00Gm6aFgXzT7omFsTsWFhqe6/F1AgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFIRNgb592H7eH93aOdESjyq9sXamMA4GA1UdDwEB/wQEAwIChDANBgkqhkiG9w0BAQsFAAOCAQEActP3325pGMnkynNbwdzlpeIPZNRYM3r5/qEInyhFZ/GrHIb5zxiLK0pe/NkK5+tiO9/+7PqhPh+yUOokfZBjlrUrO46n4fgT5cGTN79N1EXTrKbj9YtWQ0Ks0Oopkf9+1KG67hNcV1xnXg3ES/8g7YhksZVSFX1Az8FoaoO9okQPPgRdo+TwWPQuO9SCq+H5T0oLl+ZnCe7RXH4VSmPMQOBv1TzsqIZ6f/8q4rFKFSt9vHxzVg07i4j6x4+WPB01kTLVCoHSqdOGK5j7yKyPH9CchIaf8E4bxfpEwAVKiPqOHtG6XA6WNfYupyOvObvoMEesJXRulJt4g052OXQ86g==" );
        // generate the public key
        X509EncodedKeySpec spec = new X509EncodedKeySpec( yourKey );
        PublicKey publicKey = (PublicKey) kFactory.generatePublic( spec );

        System.out.println( "Public Key: " + publicKey );
        return publicKey;
    }
    
    public static Key withNimbus(String kid) throws MalformedURLException, IOException, ParseException {
        JWKSet publicKeys = JWKSet.load(new URL("https://dev-chabernac.eu.auth0.com/.well-known/jwks.json"));
        return null;
    }
    
    public static JWTClaimsSet validate(String accessToken) throws MalformedURLException, ParseException, BadJOSEException, JOSEException {
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor =
            new DefaultJWTProcessor<>();

        JWKSource<SecurityContext> keySource =
            new RemoteJWKSet<>(new URL("https://dev-chabernac.eu.auth0.com/.well-known/jwks.json"));
        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;
        JWSKeySelector<SecurityContext> keySelector =
            new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);

        jwtProcessor.setJWSKeySelector(keySelector);
        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(
            new JWTClaimsSet.Builder().issuer("https://dev-chabernac.eu.auth0.com/").build(),
            new HashSet<>(Arrays.asList("sub", "iat", "exp"))));
        JWTClaimsSet claimsSet = jwtProcessor.process(accessToken, null);
        return claimsSet;
    }
}
