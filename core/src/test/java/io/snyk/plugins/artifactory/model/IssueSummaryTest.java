package io.snyk.plugins.artifactory.model;

import io.snyk.sdk.model.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class IssueSummaryTest {

    IssueSummary summary;

  @BeforeEach
  void setUp() {
    summary = IssueSummary.from(Stream.of(
      Severity.LOW, Severity.LOW, Severity.LOW, Severity.LOW,
      Severity.MEDIUM, Severity.MEDIUM, Severity.MEDIUM,
      Severity.HIGH, Severity.HIGH,
      Severity.CRITICAL
    ));
  }

  @Test
  void getCountAtOrAbove() {
    assertEquals(1, summary.getCountAtOrAbove(Severity.CRITICAL));
    assertEquals(3, summary.getCountAtOrAbove(Severity.HIGH));
    assertEquals(6, summary.getCountAtOrAbove(Severity.MEDIUM));
    assertEquals(10, summary.getCountAtOrAbove(Severity.LOW));
  }

  @Test
  void getTotalCount() {
    assertEquals(10, summary.getTotalCount());
  }

  @Test
  void toString_withAllSeverities() {
    assertEquals("1 critical, 2 high, 3 medium, 4 low", summary.toString());
  }

  @Test
  void parse_matching() {
    Optional<IssueSummary> parsed = IssueSummary.parse(summary.toString());

    assertTrue(parsed.isPresent());
    assertEquals(1, parsed.get().getCountAtOrAbove(Severity.CRITICAL));
    assertEquals(3, parsed.get().getCountAtOrAbove(Severity.HIGH));
    assertEquals(6, parsed.get().getCountAtOrAbove(Severity.MEDIUM));
    assertEquals(10, parsed.get().getCountAtOrAbove(Severity.LOW));
  }

  @Test
  void parse_invalidInput() {
    assertFalse(IssueSummary.parse("3 medium").isPresent());
  }
}
