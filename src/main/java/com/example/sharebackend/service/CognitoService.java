package com.example.sharebackend.service;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Map;

@Service
public class CognitoService {

    @Autowired
    private AWSCognitoIdentityProvider client;

    @Value("${aws.cognito.client_id}")
    private String clientId;

    @Value("${aws.cognito.user_pool_id}")
    private String userPool;

    public SignUpResult signUp(String email, String password) {
        SignUpRequest request = new SignUpRequest().withClientId(clientId)
                .withUsername(email)
                .withPassword(password)
                .withUserAttributes(
                        new AttributeType()
                                .withName("email")
                                .withValue(email)
                );
        SignUpResult result = client.signUp(request);
        return result;
    }

    public ConfirmSignUpResult confirmSignUp(String email, String confirmationCode) {
        ConfirmSignUpRequest confirmSignUpRequest = new ConfirmSignUpRequest().withClientId(clientId).withUsername(email).withConfirmationCode(confirmationCode);
        return client.confirmSignUp(confirmSignUpRequest);
    }

    public Map<String, String> login(String email, String password) {
        Map<String, String> authParams = new LinkedHashMap<String, String>() {{
            put("USERNAME", email);
            put("PASSWORD", password);
        }};

        AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest()
                .withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
                .withUserPoolId(userPool)
                .withClientId(clientId)
                .withAuthParameters(authParams);
        AdminInitiateAuthResult authResult = client.adminInitiateAuth(authRequest);
        AuthenticationResultType resultType = authResult.getAuthenticationResult();
        return new LinkedHashMap<String, String>() {{
            put("idToken", resultType.getIdToken());
            put("accessToken", resultType.getAccessToken());
            put("refreshToken", resultType.getRefreshToken());
            put("message", "Successfully login");
        }};

    }

}
