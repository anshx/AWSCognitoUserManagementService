package com.example.sharebackend.security;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.sharebackend.exception.InvalidTokenException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.*;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(request.getServletPath().equals("/api/login")) {
            filterChain.doFilter(request, response);
        }else {
            String authorizationHeader = request.getHeader("Authorization");
            if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {

                try {
                    String token = authorizationHeader.substring("Bearer ".length());
                    validateToken(token);
//                    Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
//                    JWTVerifier verifier = JWT.require(algorithm).build();
//                    DecodedJWT decodedJWT = verifier.verify(token);
//                    String username = decodedJWT.getSubject();
//                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
//                    Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
//
//                    Arrays.stream(roles).forEach(role -> {
//                        authorities.add(new SimpleGrantedAuthority(role));
//                    });
//
//                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
//                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    filterChain.doFilter(request, response);
                } catch (Exception ex) {
                    log.error("Error message {}" + ex.getMessage());
                    Map<String, String> error = new HashMap<>();
                    error.put("error_message", ex.getMessage());
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(), error);
                }
            } else {
                filterChain.doFilter(request, response);
            }
        }
    }

    private void validateToken(String token) throws ParseException, InvalidTokenException, MalformedURLException, JwkException, JOSEException, JSONException {
        if(token == null) {
            throw new InvalidTokenException("Token is not present in the request");
        }

        SignedJWT jwt = SignedJWT.parse(token);
        JSONObject obj = new JSONObject(jwt.getPayload().toString());

        if(!obj.getString("token_use").equals("access")) {
            throw new InvalidTokenException("Token is not of type access");
        }

        validateSignature(jwt);
        validateClaims(jwt);

        String username = obj.getString("username");
        JSONArray roles = obj.getJSONArray("cognito:groups");
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();

        for(int i=0;i< roles.length();i++) {
            authorities.add(new SimpleGrantedAuthority(roles.getString(i)));
        }

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
    }

    public void validateSignature(SignedJWT jwt) throws MalformedURLException, JwkException, JOSEException, InvalidTokenException, JSONException {

        JSONObject obj = new JSONObject(jwt.getHeader().toString());
        JwkProvider provider = new UrlJwkProvider(new URL("https://cognito-idp.ap-south-1.amazonaws.com/ap-south-1_lpXy3ZUTM/.well-known/jwks.json"));

        String kid = obj.getString("kid");
        Jwk jwk = provider.get(kid);
        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) jwk.getPublicKey());

        if(!jwt.verify(verifier)) {
            throw new InvalidTokenException("Token Signature could not be verified successfully");
        }

    }

    public void validateClaims(SignedJWT jwt) throws ParseException, InvalidTokenException {
        System.out.println("inside validate claims");
        JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
        Date presentTime = new Date();

        if(!claimsSet.getExpirationTime().after(presentTime)) {
            throw new InvalidTokenException("Token has expired");
        }else if(!claimsSet.getIssuer().equals("https://cognito-idp.ap-south-1.amazonaws.com/ap-south-1_lpXy3ZUTM")) {
            throw new InvalidTokenException("Token issuer is not registered..");
        }
    }

}
