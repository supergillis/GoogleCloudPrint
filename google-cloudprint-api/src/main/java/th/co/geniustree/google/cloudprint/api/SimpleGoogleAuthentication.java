package th.co.geniustree.google.cloudprint.api;

public class SimpleGoogleAuthentication implements GoogleAuthentication {

  private final String source;
  private final String accessToken;

  public SimpleGoogleAuthentication(String source, String accessToken) {
    this.source = source;
    this.accessToken = accessToken;
  }

  public String getSource() {
    return source;
  }

  public String getAccessToken() {
    return accessToken;
  }
}
