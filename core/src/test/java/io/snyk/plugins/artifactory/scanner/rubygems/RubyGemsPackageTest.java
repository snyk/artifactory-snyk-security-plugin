package io.snyk.plugins.artifactory.scanner.rubygems;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RubyGemsPackageTest {
  @Test
  void parse() {
    assertThat(RubyGemsPackage.parse("mustermann-3.0.3.gem")).isPresent();
    assertThat(RubyGemsPackage.parse("mustermann-3.0.3.gem").get().getName()).isEqualTo("mustermann");
    assertThat(RubyGemsPackage.parse("mustermann-3.0.3.gem").get().getVersion()).isEqualTo("3.0.3");

    assertThat(RubyGemsPackage.parse("rack-protection-4.1.1.gem")).isPresent();
    assertThat(RubyGemsPackage.parse("rack-protection-4.1.1.gem").get().getName()).isEqualTo("rack-protection");
    assertThat(RubyGemsPackage.parse("rack-protection-4.1.1.gem").get().getVersion()).isEqualTo("4.1.1");
  }

  @Test
  void parse_null() {
    assertThat(RubyGemsPackage.parse(null)).isEmpty();
  }

  @Test
  void parse_invalidName() {
    assertThat(RubyGemsPackage.parse("mustermann")).isEmpty();
  }
}
