package io.snyk.plugins.artifactory.exception;

import io.snyk.sdk.api.SnykResult;
import io.snyk.sdk.model.v1.TestResult;

public class SnykAPIFailureException extends RuntimeException {
  public SnykAPIFailureException(SnykResult<TestResult> result) {
    super("Snyk API request was not successful. (" + result.statusCode + ")");
  }

  public SnykAPIFailureException(Exception cause) {
    super("Snyk API request encountered an unexpected error.", cause);
  }
}
