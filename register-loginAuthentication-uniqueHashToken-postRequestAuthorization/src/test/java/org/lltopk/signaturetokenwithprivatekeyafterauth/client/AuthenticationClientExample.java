package org.lltopk.signaturetokenwithprivatekeyafterauth.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.lltopk.signaturetokenwithprivatekeyafterauth.dto.ApiResponse;
import org.lltopk.signaturetokenwithprivatekeyafterauth.dto.LoginRequest;
import org.lltopk.signaturetokenwithprivatekeyafterauth.dto.LoginResponse;
import org.lltopk.signaturetokenwithprivatekeyafterauth.dto.RegisterRequest;
import org.lltopk.signaturetokenwithprivatekeyafterauth.util.CryptoUtil;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

/**
 * Client example demonstrating the authentication flow with server-managed keys.
 *
 * Security Model:
 * - Server generates and manages a single RSA key pair
 * - Client does NOT generate any keys
 * - Client encrypts data with server's public key
 * - No digital signature required from client
 *
 * Authentication Flow:
 * 1. Get server's public key from /api/auth/server-public-key
 * 2. Register user via /api/auth/register
 * 3. Login with encrypted credentials via /api/auth/login
 * 4. Access protected endpoints with JWT token
 */
public class AuthenticationClientExample {

    private static final String BASE_URL = "http://localhost:8080/api/auth";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private String serverPublicKey;
    private String authToken;

    public static void main(String[] args) {
        AuthenticationClientExample client = new AuthenticationClientExample();

        try {
            // Step 1: Get server's public key
            System.out.println("=== Step 1: Getting Server Public Key ===");
            client.getServerPublicKey();

            // Step 2: Register user
            System.out.println("\n=== Step 2: Registering User ===");
            client.registerUser("testuser", "securePassword123", "test@example.com");

            // Step 3: Login with encrypted credentials
            System.out.println("\n=== Step 3: Logging In ===");
            client.login("testuser", "securePassword123");

            // Step 4: Access protected endpoint
            System.out.println("\n=== Step 4: Accessing Protected Endpoint ===");
            client.getProfile();

            System.out.println("\n=== Authentication Flow Completed Successfully ===");

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Step 1: Get server's public key
     * Client must obtain server's public key before login to encrypt credentials
     */
    public void getServerPublicKey() throws Exception {
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/server-public-key"))
                .header("Content-Type", "application/json")
                .GET()
                .build();

        HttpClient client = HttpClient.newHttpClient();
        HttpResponse<String> response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());

        @SuppressWarnings("unchecked")
        Map<String, Object> responseBody = OBJECT_MAPPER.readValue(response.body(), Map.class);

        if ((Integer) responseBody.get("code") == 200) {
            Map<String, Object> data = (Map<String, Object>) responseBody.get("data");
            serverPublicKey = (String) data.get("serverPublicKey");

            System.out.println("Server Public Key obtained: " + serverPublicKey.substring(0, 50) + "...");
            System.out.println("This key will be used to encrypt all credentials before sending to server.");
        } else {
            throw new RuntimeException("Failed to get server public key: " + responseBody.get("message"));
        }
    }

    /**
     * Step 2: Register a new user
     * Note: No key generation needed on client side
     */
    public void registerUser(String username, String password, String email) throws Exception {
        RegisterRequest request = new RegisterRequest(username, password, email);

        String jsonRequest = OBJECT_MAPPER.writeValueAsString(request);
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/register"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonRequest))
                .build();

        HttpClient client = HttpClient.newHttpClient();
        HttpResponse<String> response = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());

        @SuppressWarnings("unchecked")
        Map<String, Object> responseBody = OBJECT_MAPPER.readValue(response.body(), Map.class);

        if ((Integer) responseBody.get("code") == 200) {
            Map<String, Object> data = (Map<String, Object>) responseBody.get("data");
            System.out.println("Registration successful!");
            System.out.println("User ID: " + data.get("userId"));
            System.out.println("Username: " + data.get("username"));
            System.out.println("Email: " + data.get("email"));
        } else {
            throw new RuntimeException("Registration failed: " + responseBody.get("message"));
        }
    }

    /**
     * Step 3: Login with encrypted credentials
     * 
     * Flow:
     * 1. Create data string: timestamp:nonce:password
     * 2. Encrypt with server's public key
     * 3. Send to server for authentication
     * 
     * No signature needed - server only validates encrypted data
     */
    public void login(String username, String password) throws Exception {
        // Prepare login data: timestamp:nonce:password
        long timestamp = System.currentTimeMillis();
        String nonce = UUID.randomUUID().toString();
        String dataToEncrypt = timestamp + ":" + nonce + ":" + password;

        System.out.println("Timestamp: " + timestamp);
        System.out.println("Nonce: " + nonce);

        // Encrypt data with server's public key (NO signature needed)
        String encryptedData = CryptoUtil.encryptByPublicKey(
                Base64.getDecoder().decode(serverPublicKey),
                dataToEncrypt.getBytes(StandardCharsets.UTF_8)
        );
        System.out.println("Encrypted Data: " + encryptedData.substring(0, 50) + "...");

        // Create login request (no clientPublicKey, no signature)
        LoginRequest request = new LoginRequest(
                username,
                password,
                encryptedData
        );

        // Send HTTP request
        String jsonRequest = OBJECT_MAPPER.writeValueAsString(request);
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/login"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonRequest))
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();
        HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());

        // Parse response
        ApiResponse<LoginResponse> responseBody = OBJECT_MAPPER.readValue(
                response.body(),
                ApiResponse.class
        );

        if (responseBody.getCode() == 200) {
            authToken = responseBody.getData().getToken();
            serverPublicKey = responseBody.getData().getServerPublicKey(); // Store for future use
            
            System.out.println("Login successful!");
            System.out.println("Token: " + authToken.substring(0, 50) + "...");
            System.out.println("Token Expires In: " + responseBody.getData().getExpiresIn() + " seconds");
            System.out.println("Server Public Key (save for next login): " + serverPublicKey.substring(0, 50) + "...");
        } else {
            throw new RuntimeException("Login failed: " + responseBody.getMessage());
        }
    }

    /**
     * Step 4: Access protected endpoint with JWT token
     */
    public void getProfile() throws Exception {
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/profile"))
                .header("Authorization", "Bearer " + authToken)
                .GET()
                .build();

        HttpClient httpClient = HttpClient.newHttpClient();
        HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());

        @SuppressWarnings("unchecked")
        Map<String, Object> responseBody = OBJECT_MAPPER.readValue(response.body(), Map.class);

        if ((Integer) responseBody.get("code") == 200) {
            Map<String, Object> data = (Map<String, Object>) responseBody.get("data");
            System.out.println("Profile retrieved successfully!");
            System.out.println("User ID: " + data.get("userId"));
            System.out.println("Username: " + data.get("username"));
            System.out.println("Email: " + data.get("email"));
        } else {
            throw new RuntimeException("Failed to get profile: " + responseBody.get("message"));
        }
    }

    /**
     * Helper method to create encrypted login data
     * Can be used by client applications to prepare login credentials
     * 
     * @param password user password
     * @param serverPublicKey server's RSA public key (Base64 encoded)
     * @return Map containing timestamp, nonce, and encryptedData
     */
    public static Map<String, String> createEncryptedLoginData(String password, String serverPublicKey) {
        long timestamp = System.currentTimeMillis();
        String nonce = UUID.randomUUID().toString();
        String data = timestamp + ":" + nonce + ":" + password;

        // Encrypt with server's public key
        String encryptedData = CryptoUtil.encryptByPublicKey(
                Base64.getDecoder().decode(serverPublicKey),
                data.getBytes(StandardCharsets.UTF_8)
        );

        Map<String, String> result = new HashMap<>();
        result.put("timestamp", String.valueOf(timestamp));
        result.put("nonce", nonce);
        result.put("encryptedData", encryptedData);
        result.put("serverPublicKey", serverPublicKey);

        return result;
    }
}
