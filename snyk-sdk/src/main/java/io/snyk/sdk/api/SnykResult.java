package io.snyk.sdk.api;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.util.Optional;

public class SnykResult<T> {
  public int statusCode;
  public Optional<T> result = Optional.empty();
  public Optional<String> responseAsText = Optional.empty();
  public HttpResponse<String> response;
  private static final Logger LOG = LoggerFactory.getLogger(SnykResult.class);

  public SnykResult(int statusCode, T result, String responseBody, HttpResponse<String> response) {
    this.statusCode = statusCode;
    this.result = Optional.of(result);
    this.responseAsText = Optional.of(responseBody);
    this.response = response;
  }

  public SnykResult(HttpResponse<String> response) {
    this.statusCode = response.statusCode();
    this.responseAsText = Optional.of(response.body());
    this.response = response;
  }

  public Optional<T> get() {
    return this.result;
  }

  public boolean isSuccessful() {
    return statusCode == 200;
  }

  public static <ResType> SnykResult<ResType> createResult(HttpResponse<String> response, Class<ResType> resultType) throws IOException {
    int status = response.statusCode();
    LOG.info("Snyk retrieving REST response status code: " + status);
    if (status == 200) {
      String responseBody = response.body();
      ObjectMapper objectMapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
      var res = objectMapper.readValue(responseBody, resultType);
      LOG.debug("Snyk retrieving mapped json object:\n" + res.toString());
      return new SnykResult<>(status, res, responseBody, response);
    } else {
      return new SnykResult<>(response);
    }
  }
}
