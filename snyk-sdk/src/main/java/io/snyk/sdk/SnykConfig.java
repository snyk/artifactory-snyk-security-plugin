package io.snyk.sdk;

import java.time.Duration;

public class SnykConfig {
  public final String baseUrl;
  public final String restBaseUrl;
  public final String restVersion;
  public final String token;
  public final String userAgent;
  public final boolean trustAllCertificates;
  public final String sslCertificatePath;
  public final String httpProxyHost;
  public final Integer httpProxyPort;
  public final Duration timeout;

  private SnykConfig(
    String baseUrl,
    String restBaseUrl,
    String restVersion,
    String token,
    String userAgent,
    boolean trustAllCertificates,
    String sslCertificatePath,
    String httpProxyHost,
    Integer httpProxyPort,
    Duration timeout
  ) {
    this.baseUrl = baseUrl;
    this.restBaseUrl = restBaseUrl;
    this.restVersion = restVersion;
    this.token = token;
    this.userAgent = userAgent;
    this.trustAllCertificates = trustAllCertificates;
    this.sslCertificatePath = sslCertificatePath;
    this.httpProxyHost = httpProxyHost;
    this.httpProxyPort = httpProxyPort;
    this.timeout = timeout;
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public static SnykConfig withDefaults() {
    return newBuilder().build();
  }

  public static class Builder {
    private String token;
    private String baseUrl = "https://snyk.io/api/v1/";
    private String restBaseUrl = "https://api.snyk.io/rest/";
    private String restVersion = "2024-01-23";
    private String userAgent = "snyk-sdk-java";
    private boolean trustAllCertificates = false;
    private String sslCertificatePath = "";
    private String httpProxyHost = "";
    private Integer httpProxyPort = 8080;
    private Duration timeout = Duration.ofMillis(60_000);

    private Builder() {
    }

    public Builder setToken(String token) {
      this.token = token;
      return this;
    }

    public Builder setBaseUrl(String baseUrl) {
      this.baseUrl = baseUrl;
      return this;
    }

    public Builder setRestBaseUrl(String restBaseUrl) {
      this.restBaseUrl = restBaseUrl;
      return this;
    }

    public Builder setRestVersion(String restVersion) {
      this.restVersion = restVersion;
      return this;
    }

    public Builder setUserAgent(String userAgent) {
      this.userAgent = userAgent;
      return this;
    }

    public Builder setTrustAllCertificates(boolean trustAllCertificates) {
      this.trustAllCertificates = trustAllCertificates;
      return this;
    }

    public Builder setSslCertificatePath(String sslCertificatePath) {
      this.sslCertificatePath = sslCertificatePath;
      return this;
    }

    public Builder setHttpProxyHost(String httpProxyHost) {
      this.httpProxyHost = httpProxyHost;
      return this;
    }

    public Builder setHttpProxyPort(Integer httpProxyPort) {
      this.httpProxyPort = httpProxyPort;
      return this;
    }

    public Builder setTimeout(Duration timeout) {
      this.timeout = timeout;
      return this;
    }

    public SnykConfig build() {
      return new SnykConfig(
        baseUrl,
        restBaseUrl,
        restVersion,
        token,
        userAgent,
        trustAllCertificates,
        sslCertificatePath,
        httpProxyHost,
        httpProxyPort,
        timeout
      );
    }
  }
}
