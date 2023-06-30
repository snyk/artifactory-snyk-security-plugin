package io.snyk.sdk.model.v3;

import com.fasterxml.jackson.annotation.JsonValue;

public enum IssueType {
  ISSUE("issue"),
  LICENSE("license");

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
