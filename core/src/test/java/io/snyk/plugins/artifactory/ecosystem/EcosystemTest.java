package io.snyk.plugins.artifactory.ecosystem;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

class EcosystemTest {

  @Test
  void ecosystemByPackageType() {
    assertThat(Ecosystem.fromPackageType("maven")).contains(Ecosystem.MAVEN);
    assertThat(Ecosystem.fromPackageType("npm")).contains(Ecosystem.NPM);
    assertThat(Ecosystem.fromPackageType("pypi")).contains(Ecosystem.PYPI);
    assertThat(Ecosystem.fromPackageType("nuget")).isEmpty();
  }
}
