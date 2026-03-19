package io.snyk.plugins.artifactory.configuration.properties;

public final class BlockReasonProperty {

  /** Max length for a single property value. */
  public static final int MAX_STORED_LENGTH = 2400;

  private BlockReasonProperty() {
  }

  public static String truncateForStorage(String message) {
    if (message == null || message.isEmpty()) {
      return "";
    }
    if (message.length() <= MAX_STORED_LENGTH) {
      return message;
    }
    return message.substring(0, MAX_STORED_LENGTH - 3) + "...";
  }
}
