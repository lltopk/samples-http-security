package org.lltopk.signaturetokenwithprivatekeyafterauth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Login response DTO.
 * Returns JWT token and server's public key for client to use in future requests.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class LoginResponse {
    private String token;
    private String userId;
    private String username;
    private Long expiresIn;
    private String serverPublicKey;
}
