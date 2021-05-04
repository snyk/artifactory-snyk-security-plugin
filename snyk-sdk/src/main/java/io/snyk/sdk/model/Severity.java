package io.snyk.sdk.model;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The Snyk defined severity level: "critical", "high", "medium" or "low".
 */
public enum Severity {
  LOW("low"),
  MEDIUM("medium"),
  HIGH("high"),
  CRITICAL("critical");

  private final String level;

  Severity(String level) {
    this.level = level;
  }

  @JsonValue
  public String getSeverityLevel() {
    return level;
  }

  public static Severity of(String level) {
    for (Severity value : values()) {
      if (value.level.equals(level)) {
        return value;
      }
    }
    return null;
  }
}
