package io.snyk.sdk.model;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The Snyk defined severity level: "high", "medium" or "low".
 */
public enum Severity {
  LOW("low"),
  MEDIUM("medium"),
  HIGH("high");

  private final String level;

  Severity(String level) {
    this.level = level;
  }

  @JsonValue
  public String getSeverityLevel() {
    return level;
  }
}
