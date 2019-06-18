package io.snyk.sdk.model;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The issue type: "license" or "vulnerability".
 */
public enum IssueType {
  LICENSE("license"),
  VULNERABILITY("vuln");

  private final String type;

  IssueType(String type) {
    this.type = type;
  }

  @JsonValue
  public String getIssueType() {
    return type;
  }

  public static IssueType of(String type) {
    for (IssueType value : values()) {
      if (value.type.equals(type)) {
        return value;
      }
    }
    return null;
  }
}
