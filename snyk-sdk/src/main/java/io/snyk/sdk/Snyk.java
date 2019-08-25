package io.snyk.sdk;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.snyk.sdk.api.v1.SnykClient;
import io.snyk.sdk.config.UnsafeSSLConfiguration;
import io.snyk.sdk.interceptor.ServiceInterceptor;
import okhttp3.OkHttpClient;
import retrofit2.Retrofit;
import retrofit2.converter.jackson.JacksonConverterFactory;

import static java.util.concurrent.TimeUnit.MILLISECONDS;

public class Snyk {

  private static final String DEFAULT_BASE_URL = "https://snyk.io/api/v1/";
  private static final String DEFAULT_USER_AGENT = "snyk-sdk-java";
  private static final long DEFAULT_CONNECTION_TIMEOUT = 30_000L;
  private static final long DEFAULT_READ_TIMEOUT = 60_000L;
  private static final long DEFAULT_WRITE_TIMEOUT = 60_000L;

  private final Retrofit retrofit;

  private Snyk(Config config) throws NoSuchAlgorithmException, KeyManagementException {
    if (config.token == null || config.token.isEmpty()) {
      throw new IllegalArgumentException("Snyk API token is empty");
    }

    OkHttpClient.Builder builder = new OkHttpClient.Builder().connectTimeout(DEFAULT_CONNECTION_TIMEOUT, MILLISECONDS)
                                                             // .hostnameVerifier()
                                                             .readTimeout(DEFAULT_READ_TIMEOUT, MILLISECONDS)
                                                             .writeTimeout(DEFAULT_WRITE_TIMEOUT, MILLISECONDS);

    if (config.trustAllCertificates) {
      SSLContext sslContext = SSLContext.getInstance("TLS");
      TrustManager[] trustManagers = UnsafeSSLConfiguration.buildUnsafeTrustManager();
      sslContext.init(null, trustManagers, new SecureRandom());
      SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
      builder.sslSocketFactory(sslSocketFactory, (X509TrustManager) trustManagers[0]);
    }

    builder.addInterceptor(new ServiceInterceptor(config.token, config.userAgent));
    ObjectMapper objectMapper = new ObjectMapper();
    objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    retrofit = new Retrofit.Builder().client(builder.build())
                                     .baseUrl(config.baseUrl)
                                     .addConverterFactory(JacksonConverterFactory.create(objectMapper))
                                     .build();
  }

  public static Snyk newBuilder(Config config) throws NoSuchAlgorithmException, KeyManagementException {
    return new Snyk(config);
  }

  public SnykClient buildSync() {
    return retrofit.create(SnykClient.class);
  }

  public static final class Config {
    String baseUrl;
    String token;
    String userAgent;
    boolean trustAllCertificates;

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
      this.baseUrl = baseUrl;
      this.token = token;
      this.userAgent = userAgent;
      this.trustAllCertificates = trustAllCertificates;
    }
  }
}
