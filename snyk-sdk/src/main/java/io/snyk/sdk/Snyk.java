package io.snyk.sdk;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.SecureRandom;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.snyk.sdk.api.v1.SnykClient;
import io.snyk.sdk.config.SSLConfiguration;
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

  private Snyk(Config config) throws Exception {
    if (config.token == null || config.token.isEmpty()) {
      throw new IllegalArgumentException("Snyk API token is empty");
    }

    OkHttpClient.Builder builder = new OkHttpClient.Builder().connectTimeout(DEFAULT_CONNECTION_TIMEOUT, MILLISECONDS)
                                                             .readTimeout(DEFAULT_READ_TIMEOUT, MILLISECONDS)
                                                             .writeTimeout(DEFAULT_WRITE_TIMEOUT, MILLISECONDS);

    if (config.trustAllCertificates) {
      SSLContext sslContext = SSLContext.getInstance("TLS");
      TrustManager[] trustManagers = SSLConfiguration.buildUnsafeTrustManager();
      sslContext.init(null, trustManagers, new SecureRandom());
      SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
      builder.sslSocketFactory(sslSocketFactory, (X509TrustManager) trustManagers[0]);
    } else if (config.sslCertificatePath != null && !config.sslCertificatePath.isEmpty()) {
      SSLContext sslContext = SSLContext.getInstance("TLS");
      X509TrustManager trustManager = SSLConfiguration.buildCustomTrustManager(config.sslCertificatePath);
      sslContext.init(null, new TrustManager[]{trustManager}, null);
      SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
      builder.sslSocketFactory(sslSocketFactory, (X509TrustManager) trustManager);
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

  public static Snyk newBuilder(Config config) throws Exception {
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
    String sslCertificatePath;

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
      this.baseUrl = baseUrl;
      this.token = token;
      this.userAgent = userAgent;
      this.trustAllCertificates = trustAllCertificates;
      this.sslCertificatePath = sslCertificatePath;
    }
  }
}
