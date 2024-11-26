package io.snyk.plugins.artifactory.scanner.cocoapods;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class CocoapodsPackageTest {

  @Test
  void parse() {
    Optional<CocoapodsPackage> pckg = CocoapodsPackage.parse(
        "Bolts-ObjC-1.9.1.tar.gz"
    );

    assertThat(pckg).isNotEmpty();
    assertThat(pckg.get().getName()).isEqualTo("Bolts-ObjC");
    assertThat(pckg.get().getVersion()).isEqualTo("1.9.1");
  }

  @Test
  void parse_unexpectedPackageName() {
    assertThat(CocoapodsPackage.parse("3.5.1.tar.gz")).isEmpty();
  }

  @Test
  void parse_null() {
    assertThat(CocoapodsPackage.parse(null)).isEmpty();
  }
}
