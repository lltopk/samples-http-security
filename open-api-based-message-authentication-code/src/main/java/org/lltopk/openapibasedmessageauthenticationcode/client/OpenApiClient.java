package org.lltopk.openapibasedmessageauthenticationcode.client;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;
import java.util.UUID;

public class OpenApiClient {
    private final String baseUrl;
    private final String appKey;
    private final String appSecret;

    public OpenApiClient(String baseUrl, String appKey, String appSecret) {
        this.baseUrl = baseUrl;
        this.appKey = appKey;
        this.appSecret = appSecret;
    }

    public String doGet(String path, Map<String, String> params)
            throws Exception {
        String sortedQuery = buildSortedQuery(params);
        String fullUrl = baseUrl + path;
        if (!sortedQuery.isEmpty()) {
            fullUrl += "?" + sortedQuery;
        }

        String timestamp = String.valueOf(System.currentTimeMillis());
        String nonce = UUID.randomUUID().toString().replace("-", "");

        // 待签名的路径要包含排序后的查询参数
        String signPath = sortedQuery.isEmpty()
                ? path : path + "?" + sortedQuery;

        // 拼接待签名字符串
        String stringToSign = "GET" + "\n"
                + signPath + "\n"
                + timestamp + "\n"
                + nonce + "\n";

        String signature = hmacSha256(stringToSign, appSecret);

        // 设置签名Header，发送请求
        URL url = new URL(fullUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("X-App-Key", appKey);
        conn.setRequestProperty("X-Timestamp", timestamp);
        conn.setRequestProperty("X-Nonce", nonce);
        conn.setRequestProperty("X-Signature", signature);

        return readResponse(conn);
    }

    private String hmacSha256(String stringToSign, String appSecret) {
        return null;
    }

    private String readResponse(HttpURLConnection conn) {
        return null;
    }

    private String buildSortedQuery(Map<String, String> params) {
        return null;
    }
}
