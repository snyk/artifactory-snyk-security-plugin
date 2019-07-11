package io.snyk.sdk.interceptor;

import javax.annotation.Nonnull;
import java.io.IOException;

import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;

public class ServiceInterceptor implements Interceptor {

  private final String token;
  private final String userAgent;

  public ServiceInterceptor(String token, String userAgent) {
    this.token = token;
    this.userAgent = userAgent;
  }

  @Nonnull
  @Override
  public Response intercept(@Nonnull Chain chain) throws IOException {
    Request.Builder builder = chain.request().newBuilder();

    builder.addHeader("Accept", "application/json")
           .addHeader("Authorization", "token " + token)
           .addHeader("Content-Type", "application/json")
           .addHeader("User-Agent", userAgent);

    return chain.proceed(builder.build());
  }
}
