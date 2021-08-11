package io.snyk.sdk;

import java.time.Duration;

public class Snyk {
  private static final String DEFAULT_BASE_URL = "https://snyk.io/api/v1/";
  private static final String DEFAULT_USER_AGENT = "snyk-sdk-java";

  public static final class Config {
    public String baseUrl;
    public String token;
    public String userAgent;
    public boolean trustAllCertificates;
    public String sslCertificatePath;
    public String httpProxyHost;
    public Integer httpProxyPort;
    public Duration timeout;

    public Config(String token) {
      this(DEFAULT_BASE_URL, token);
    }

    public Config(String baseUrl, String token) {
      this(baseUrl, token, DEFAULT_USER_AGENT);
    }

    public Config(String baseUrl, String token, String userAgent) {
      this(baseUrl, token, userAgent, false);
    }

    public Config(String baseUrl, String token, String userAgent, boolean trustAllCertificates) {
      this(baseUrl, token, userAgent, trustAllCertificates, "");
    }

    public Config(String baseUrl, String token, String userAgent, boolean trustAllCertificates, String sslCertificatePath) {
      this(baseUrl, token, userAgent, trustAllCertificates, sslCertificatePath, "", 8080, Duration.ofMillis(60_000));
    }

    public Config(String baseUrl, String token, String userAgent, boolean trustAllCertificates, String sslCertificatePath, String httpProxyHost, Integer httpProxyPort, Duration timeout) {
      this.baseUrl = baseUrl;
      this.token = token;
      this.userAgent = userAgent;
      this.trustAllCertificates = trustAllCertificates;
      this.sslCertificatePath = sslCertificatePath;
      this.httpProxyHost = httpProxyHost;
      this.httpProxyPort = httpProxyPort;
      this.timeout = timeout;
    }
  }
}
