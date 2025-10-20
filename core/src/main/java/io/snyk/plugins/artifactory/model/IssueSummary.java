package io.snyk.plugins.artifactory.model;

import io.snyk.sdk.model.Issue;
import io.snyk.sdk.model.Severity;
import io.snyk.sdk.model.purl.PurlIssue;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.lang.Integer.parseInt;
import static java.lang.String.format;

public class IssueSummary {

  private static final Pattern pattern = Pattern.compile("(\\d+) critical, (\\d+) high, (\\d+) medium, (\\d+) low");

  private final Map<Severity, Integer> countBySeverity;

  private IssueSummary(Map<Severity, Integer> countBySeverity) {
    this.countBySeverity = countBySeverity;
  }

  public static IssueSummary fromPurlIssues(List<PurlIssue> issues) {
    return IssueSummary.from(
      issues.stream()
        .filter(i -> (i.attribute != null && (i.attribute.isIgnored == null || !i.attribute.isIgnored))
          && (i.isIgnored == null || !i.isIgnored))
        .map(i -> i.attribute.severity)
    );
  }

  public static IssueSummary from(List<? extends Issue> issues) {
    return IssueSummary.from(
      issues.stream()
      .filter(i -> i.isIgnored == null || !i.isIgnored)
      .map(i -> i.severity));
  }

  public static IssueSummary from(Stream<Severity> severities) {
    return new IssueSummary(severities.collect(Collectors.toMap(s -> s, s -> 1, Integer::sum)));
  }

  public static Optional<IssueSummary> parse(String stringifiedSummary) {
    Matcher matcher = pattern.matcher(stringifiedSummary);
    if(!matcher.matches()) {
      return Optional.empty();
    }
    HashMap<Severity, Integer> countBySeverity = new HashMap<>();
    countBySeverity.put(Severity.CRITICAL, parseInt(matcher.group(1)));
    countBySeverity.put(Severity.HIGH, parseInt(matcher.group(2)));
    countBySeverity.put(Severity.MEDIUM, parseInt(matcher.group(3)));
    countBySeverity.put(Severity.LOW, parseInt(matcher.group(4)));
    return Optional.of(new IssueSummary(countBySeverity));
  }

  public int getCountAtOrAbove(Severity severity) {
    int total = 0;
    for (Severity value : Arrays.asList(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)) {
      total += getCountBySeverity(value);
      if (value == severity) {
        return total;
      }
    }
    return total;
  }

  private int getCountBySeverity(Severity severity) {
    return countBySeverity.getOrDefault(severity, 0);
  }

  public int getTotalCount() {
    return getCountAtOrAbove(Severity.LOW);
  }

  @Override
  public String toString() {
    return format("%d critical, %d high, %d medium, %d low",
            getCountBySeverity(Severity.CRITICAL),
            getCountBySeverity(Severity.HIGH),
            getCountBySeverity(Severity.MEDIUM),
            getCountBySeverity(Severity.LOW)
    );
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    IssueSummary summary = (IssueSummary) o;
    return toString().equals(summary.toString());
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(countBySeverity);
  }
}
