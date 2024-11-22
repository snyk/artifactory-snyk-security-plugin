package io.snyk.plugins.artifactory.ecosystem;

import org.junit.jupiter.api.Test;

import static io.snyk.plugins.artifactory.ecosystem.Ecosystem.match;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

class EcosystemTest {

  @Test
  void ecosystemByPackageType() {
    assertThat(match("maven", "")).contains(Ecosystem.MAVEN);
    assertThat(match("npm", "")).contains(Ecosystem.NPM);
    assertThat(match("pypi", "")).contains(Ecosystem.PYPI);
    assertThat(match("gems", "gems/rack-protection-4.1.1.gem")).contains(Ecosystem.RUBYGEMS);
    assertThat(match("nuget", "")).isEmpty();
  }

  @Test
  void gems_noMatchWhenNoExtension() {
    assertThat(match("gems", "gems/rack-protection")).isEmpty();
  }
}
