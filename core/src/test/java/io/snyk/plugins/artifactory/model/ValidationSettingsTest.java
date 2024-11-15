package io.snyk.plugins.artifactory.model;

import io.snyk.sdk.model.Severity;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

class ValidationSettingsTest {

  @Test
  void from_whenValidThresholds() {
    ValidationSettings settings = ValidationSettings.from("high", "low");

    assertThat(settings.getVulnSeverityThreshold()).contains(Severity.HIGH);
    assertThat(settings.getLicenseSeverityThreshold()).contains(Severity.LOW);
  }

  @Test
  void from_whenInvalidThresholds() {
    assertThatThrownBy(() -> ValidationSettings.from("danger", "low"))
      .hasMessageContaining("danger");
  }

  @Test
  void from_whenNoThresholds() {
    ValidationSettings settings = ValidationSettings.from("none", "none");

    assertThat(settings.getVulnSeverityThreshold()).isEmpty();
    assertThat(settings.getLicenseSeverityThreshold()).isEmpty();
  }


}
