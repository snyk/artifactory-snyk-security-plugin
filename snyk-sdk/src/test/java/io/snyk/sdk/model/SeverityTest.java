package io.snyk.sdk.model;
import org.junit.jupiter.api.Test;

import static io.snyk.sdk.model.Severity.*;
import static org.junit.jupiter.api.Assertions.*;

class SeverityTest {

  @Test
  void isAtLeastAsSevereAsLow() {
    assertFalse(LOW.isAtLeastAsSevereAs(CRITICAL));
    assertFalse(LOW.isAtLeastAsSevereAs(HIGH));
    assertFalse(LOW.isAtLeastAsSevereAs(MEDIUM));
    assertTrue(LOW.isAtLeastAsSevereAs(LOW));
  }

  @Test
  void isAtLeastAsSevereAsMEDIUM() {
    assertFalse(MEDIUM.isAtLeastAsSevereAs(CRITICAL));
    assertFalse(MEDIUM.isAtLeastAsSevereAs(HIGH));
    assertTrue(MEDIUM.isAtLeastAsSevereAs(MEDIUM));
    assertTrue(MEDIUM.isAtLeastAsSevereAs(LOW));
  }

  @Test
  void isAtLeastAsSevereAsHIGH() {
    assertFalse(HIGH.isAtLeastAsSevereAs(CRITICAL));
    assertTrue(HIGH.isAtLeastAsSevereAs(HIGH));
    assertTrue(HIGH.isAtLeastAsSevereAs(MEDIUM));
    assertTrue(HIGH.isAtLeastAsSevereAs(LOW));
  }

  @Test
  void isAtLeastAsSevereAsCRITICAL() {
    assertTrue(CRITICAL.isAtLeastAsSevereAs(CRITICAL));
    assertTrue(CRITICAL.isAtLeastAsSevereAs(HIGH));
    assertTrue(CRITICAL.isAtLeastAsSevereAs(MEDIUM));
    assertTrue(CRITICAL.isAtLeastAsSevereAs(LOW));
  }

}
