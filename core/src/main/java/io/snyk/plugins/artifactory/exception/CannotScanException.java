package io.snyk.plugins.artifactory.exception;

public class CannotScanException extends RuntimeException {
  public CannotScanException(String reason) {
    super(reason);
  }

  public CannotScanException(String reason, Exception e) {
    super(reason, e);
  }
}
