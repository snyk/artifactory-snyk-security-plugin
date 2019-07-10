package io.snyk.plugins.artifactory.exception;

public class SnykRuntimeException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  public SnykRuntimeException(String message, Throwable cause) {
    super(message, cause);
  }
}
