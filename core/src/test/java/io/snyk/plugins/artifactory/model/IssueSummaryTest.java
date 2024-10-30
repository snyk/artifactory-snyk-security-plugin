package io.snyk.plugins.artifactory.model;

import io.snyk.sdk.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class IssueSummaryTest {

  @Test
  void getCountAtOrAbove() {
    IssueSummary summary = IssueSummary.from(Stream.of(
      Severity.LOW, Severity.LOW, Severity.LOW, Severity.LOW,
      Severity.MEDIUM, Severity.MEDIUM, Severity.MEDIUM,
      Severity.HIGH, Severity.HIGH,
      Severity.CRITICAL
    ));

    assertEquals(1, summary.getCountAtOrAbove(Severity.CRITICAL));
    assertEquals(3, summary.getCountAtOrAbove(Severity.HIGH));
    assertEquals(6, summary.getCountAtOrAbove(Severity.MEDIUM));
    assertEquals(10, summary.getCountAtOrAbove(Severity.LOW));
  }
}
