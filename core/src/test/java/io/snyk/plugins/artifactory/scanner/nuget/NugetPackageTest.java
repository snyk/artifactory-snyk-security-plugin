package io.snyk.plugins.artifactory.scanner.nuget;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class NugetPackageTest {

  @Test
  void parse() {
    Optional<NugetPackage> pkg = NugetPackage.parse("newtonsoft.json.13.10.2.nupkg");

    assertThat(pkg).isNotEmpty();
    assertThat(pkg.get().getName()).isEqualTo("newtonsoft.json");
    assertThat(pkg.get().getVersion()).isEqualTo("13.10.2");
  }

  @Test
  void parse_unexpectedInput() {
    assertThat(NugetPackage.parse("newtonsoft.json.nupkg")).isEmpty();
  }

  @Test
  void parse_null() {
    assertThat(NugetPackage.parse(null)).isEmpty();
  }
}
