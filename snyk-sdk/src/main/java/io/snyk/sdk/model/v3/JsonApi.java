package io.snyk.sdk.model.v3;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;

public class JsonApi implements Serializable {
  private static final long serialVersionUID = 1L;

  @JsonProperty
  private String version;
}
