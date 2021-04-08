package io.snyk.sdk.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
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


  @JsonIgnore
  public boolean isAtLeastAsSevereAs(Severity threshold) {
    switch (threshold) {
      case LOW:
        return true;
      case MEDIUM:
        return this != LOW;
      case HIGH:
        return (this != LOW) && (this != MEDIUM);
      case CRITICAL:
        return this == CRITICAL;
    }
    return false;
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
