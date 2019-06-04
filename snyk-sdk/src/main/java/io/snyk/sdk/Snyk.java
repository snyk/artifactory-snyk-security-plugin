package io.snyk.sdk;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.snyk.sdk.api.v1.SnykClient;
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

  private Snyk(Config config) {
    if (config.token == null || config.token.isEmpty()) {
      throw new IllegalArgumentException("Snyk API token is empty");
    }

    OkHttpClient.Builder builder = new OkHttpClient.Builder().connectTimeout(DEFAULT_CONNECTION_TIMEOUT, MILLISECONDS)
                                                             .readTimeout(DEFAULT_READ_TIMEOUT, MILLISECONDS)
                                                             .writeTimeout(DEFAULT_WRITE_TIMEOUT, MILLISECONDS);
    builder.addInterceptor(new ServiceInterceptor(config.token, config.userAgent));
    ObjectMapper objectMapper = new ObjectMapper();
    objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    retrofit = new Retrofit.Builder().client(builder.build())
                                     .baseUrl(config.baseUrl)
                                     .addConverterFactory(JacksonConverterFactory.create(objectMapper))
                                     .build();
  }

  public static Snyk newBuilder(Config config) {
    return new Snyk(config);
  }

  public SnykClient buildSync() {
    return retrofit.create(SnykClient.class);
  }

  public static final class Config {
    String baseUrl;
    String token;
    String userAgent;

    public Config(String token) {
      this.baseUrl = DEFAULT_BASE_URL;
      this.token = token;
      this.userAgent = DEFAULT_USER_AGENT;
    }

    public Config(String baseUrl, String token) {
      this.baseUrl = baseUrl;
      this.token = token;
      this.userAgent = DEFAULT_USER_AGENT;
    }
  }
}
