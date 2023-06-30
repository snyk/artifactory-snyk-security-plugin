package io.snyk.plugins.artifactory.exception;

import io.snyk.sdk.api.SnykResult;

public class SnykAPIFailureException extends RuntimeException {
  public SnykAPIFailureException(SnykResult<?> result) {
    super("Snyk API request was not successful. (" + result.statusCode + ")");
  }

  public SnykAPIFailureException(Exception cause) {
    super("Snyk API request encountered an unexpected error.", cause);
  }
}
