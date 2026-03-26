package org.lltopk.signaturetokenwithprivatekeyafterauth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Login request DTO.
 * Client encrypts data with server's public key (no signature needed).
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class LoginRequest {

    @NotBlank(message = "Username cannot be empty")
    private String username;

    /**
     * 公钥加密后的密码
     */
    @NotBlank(message = "Encrypted data cannot be empty")
    private String encryptedData;
}
