package io.snyk.plugins.artifactory.scanner.npm;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class NpmPackageTest {

  @Test
  void parse() {
    Optional<NpmPackage> pkg = NpmPackage.parse("npm:lodash/-/lodash-4.17.15.tgz");

    assertThat(pkg).isNotEmpty();
    assertThat(pkg.get().getName()).isEqualTo("lodash");
    assertThat(pkg.get().getVersion()).isEqualTo("4.17.15");
  }

  @Test
  void parse_withScope() {
    Optional<NpmPackage> pkg = NpmPackage.parse("npm:@snyk/protect/-/protect-1.675.0.tgz");

    assertThat(pkg).isNotEmpty();
    assertThat(pkg.get().getName()).isEqualTo("@snyk/protect");
    assertThat(pkg.get().getVersion()).isEqualTo("1.675.0");
  }

  @Test
  void parse_withVersionPostfix() {
    Optional<NpmPackage> pkg = NpmPackage.parse("npm:@babel/core/-/core-7.0.0-rc.4.tgz");

    assertThat(pkg).isNotEmpty();
    assertThat(pkg.get().getName()).isEqualTo("@babel/core");
    assertThat(pkg.get().getVersion()).isEqualTo("7.0.0-rc.4");
  }

  @Test
  void parse_unexpectedInput() {
    assertThat(NpmPackage.parse("lodash-4.17.15.tgz")).isEmpty();
  }

  @Test
  void parse_null() {
    assertThat(NpmPackage.parse(null)).isEmpty();
  }
}

