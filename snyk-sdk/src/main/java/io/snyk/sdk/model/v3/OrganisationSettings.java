package io.snyk.sdk.model.v3;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;

public class OrganisationSettings implements Serializable {
  private static final long serialVersionUID = 1L;

  @JsonProperty("data")
  private OrganisationSettingsData data;

  @JsonProperty("jsonapi")
  private JsonApi jsonApi;

  @JsonProperty("links")
  private Links links;
}

class OrganisationSettingsData implements Serializable {
  private static final long serialVersionUID = 1L;

  private OrganisationSettingsAttributes attributes;
  private String id;
  private String type;
}

class OrganisationSettingsAttributes implements Serializable {
  private static final long serialVersionUID = 1L;

  @JsonProperty("is_personal")
  private boolean isPersonal;
  private String name;
  private String slug;
}

