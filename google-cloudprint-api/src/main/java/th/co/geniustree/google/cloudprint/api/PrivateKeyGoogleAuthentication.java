package th.co.geniustree.google.cloudprint.api;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */


import com.google.api.client.util.Base64;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import th.co.geniustree.google.cloudprint.api.exception.GoogleAuthenticationException;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;

/**
 *
 * @author jittagorn pitakmetagoon
 */
public class PrivateKeyGoogleAuthentication implements GoogleAuthentication {

    private static final Logger LOG = LoggerFactory.getLogger(PrivateKeyGoogleAuthentication.class);
    public static final String LOGIN_URL = "https://www.googleapis.com/oauth2/v3/token";
    private String source;
    private String accessToken;

    private PrivateKeyGoogleAuthentication() {
    }

    public PrivateKeyGoogleAuthentication(String source) {
        this.source = source;
    }

    /**
     * For login Google Service<br/>
     * <a href='https://developers.google.com/accounts/docs/AuthForInstalledApps'>https://developers.google.com/accounts/docs/AuthForInstalledApps</a>
     *
     * @param privateKeyPath Google Account or Google Email
     * @param privateKeyName Email Password
     * @throws GoogleAuthenticationException
     */
    public void login(String privateKeyPath, String privateKeyName, String email) throws GoogleAuthenticationException {
        try {

            long unixTimestamp = System.currentTimeMillis()/1000L;

            String jwtHeader = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
            String jwtClaim = "{" +
                    "\"iss\":\""+email+"\"," +
                    "\"scope\":\"https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/cloudprint\"," +
                    "\"aud\":\"https://www.googleapis.com/oauth2/v3/token\"," +
                    "\"exp\":"+(unixTimestamp+600)+"," +
                    "\"iat\":"+unixTimestamp+"" +
                    "}";


            String jwtPart = new StringBuilder().append(Base64.encodeBase64URLSafeString(jwtHeader.getBytes(StandardCharsets.UTF_8))).append(".").append(Base64.encodeBase64URLSafeString(jwtClaim.getBytes(StandardCharsets.UTF_8))).toString();

            Signature signature = Signature.getInstance("SHA256withRSA");
            KeyStore keystore = KeyStore.getInstance("PKCS12");
//            keystore.load(new FileInputStream(new File("conf/google.p12")), "notasecret".toCharArray());
//            PrivateKey privateKey = (PrivateKey)keystore.getKey("privatekey", "notasecret".toCharArray());
            keystore.load(new FileInputStream(new File(privateKeyPath)), "notasecret".toCharArray());
            PrivateKey privateKey = (PrivateKey)keystore.getKey(privateKeyName, "notasecret".toCharArray());
            signature.initSign(privateKey);

            signature.update(jwtPart.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = signature.sign();

            String jwt = jwtPart+"."+Base64.encodeBase64URLSafeString(signatureBytes);

            String postData = "grant_type="+ URLEncoder.encode("urn:ietf:params:oauth:grant-type:jwt-bearer", "UTF-8")+"&assertion="+jwt;

            LOG.info("Sending OAuth2 authorization request");
            URL url = new URL(LOGIN_URL);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setInstanceFollowRedirects(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("charset", "utf-8");
            conn.setUseCaches(false);
            DataOutputStream wr = new DataOutputStream(conn.getOutputStream());
            wr.write(postData.getBytes(StandardCharsets.UTF_8));

            StringBuilder response = new StringBuilder();
            BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();


            JsonParser parser = new JsonParser();
            JsonObject json = (JsonObject)parser.parse(response.toString());
            String accessToken = json.get("access_token").getAsString();

            this.accessToken = accessToken;

        } catch (Exception ex) {
            throw new GoogleAuthenticationException(ex);
        }
    }

    public String getSource() {
        return source;
    }

    public String getAccessToken() {
        return accessToken;
    }
}
