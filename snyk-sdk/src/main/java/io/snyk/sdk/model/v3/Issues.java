package io.snyk.sdk.model.v3;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.List;

public class Issues implements Serializable {
  private static final long serialVersionUID = 1L;

  @JsonProperty("data")
  private IssuesData data;

  @JsonProperty("jsonapi")
  private JsonApi jsonApi;

  @JsonProperty("links")
  private Links links;
}

class IssuesData implements Serializable {
  private static final long serialVersionUID = 1L;

  private IssuesAttributes attributes;
  private String id;
  private String type;
}

class IssuesAttributes implements Serializable {
  private static final long serialVersionUID = 1L;

  private String key;
  private String title;
  private String type;

  @JsonProperty("created_at")
  private String createdAt;

  @JsonProperty("updated_at")
  private String updatedAt;

  private String description;
  private List<Problem> problems;
  private List<Coordinate> coordinates;
  private List<Severity> severities;

  @JsonProperty("effective_severity_level")
  private String effectiveSeverityLevel;

  private Slots slots;
}

class Problem implements Serializable {
  private static final long serialVersionUID = 1L;
  private String id;
  private String source;
}

class Coordinate implements Serializable {
  private static final long serialVersionUID = 1L;
  private List<Remedy> remedies;
  private List<String> representation;
}

class Remedy implements Serializable {
  private static final long serialVersionUID = 1L;
  private String type;
  private String description;
  private Details details;
}

class Details implements Serializable {
  private static final long serialVersionUID = 1L;
  @JsonProperty("upgrade_package")
  private String upgradePackage;
}

class Severity implements Serializable {
  private static final long serialVersionUID = 1L;
  private String source;
  private String level;
  private double score;
  private String vector;
}

class Slots implements Serializable {
  private static final long serialVersionUID = 1L;
  @JsonProperty("disclosure_time")
  private String disclosureTime;
  private String exploit;

  @JsonProperty("publication_time")
  private String publicationTime;

  private List<Reference> references;
}

class Reference implements Serializable {
  private static final long serialVersionUID = 1L;
  private String url;
  private String title;
}
