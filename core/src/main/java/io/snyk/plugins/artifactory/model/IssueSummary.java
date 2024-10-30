package io.snyk.plugins.artifactory.model;

import io.snyk.sdk.model.Issue;
import io.snyk.sdk.model.Severity;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class IssueSummary {

  private final Map<Severity, Integer> countBySeverity;

  private IssueSummary(Map<Severity, Integer> countBySeverity) {
    this.countBySeverity = countBySeverity;
  }

  public static IssueSummary from(List<? extends Issue> issues) {
    return IssueSummary.from(issues.stream().map(i -> i.severity));
  }

  public static IssueSummary from(Stream<Severity> severities) {
    return new IssueSummary(severities.collect(Collectors.toMap(s -> s, s -> 1, Integer::sum)));
  }

  public int getCountAtOrAbove(Severity severity) {
    int total = 0;
    for (Severity value : Arrays.asList(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)) {
      total += getBySeverity(value);
      if (value == severity) {
        return total;
      }
    }
    return total;
  }

  private int getBySeverity(Severity severity) {
    return countBySeverity.getOrDefault(severity, 0);
  }
}
