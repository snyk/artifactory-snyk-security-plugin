package io.snyk.plugins.artifactory.configuration.properties;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class BlockReasonPropertyTest {

  @Test
  void truncateForStorage_nullOrEmpty() {
    assertThat(BlockReasonProperty.truncateForStorage(null)).isEmpty();
    assertThat(BlockReasonProperty.truncateForStorage("")).isEmpty();
  }

  @Test
  void truncateForStorage_shortMessageUnchanged() {
    String msg = "Artifact has vulnerabilities";
    assertThat(BlockReasonProperty.truncateForStorage(msg)).isEqualTo(msg);
  }

  @Test
  void truncateForStorage_longMessageEndsWithEllipsis() {
    String longMsg = "x".repeat(BlockReasonProperty.MAX_STORED_LENGTH + 100);
    String out = BlockReasonProperty.truncateForStorage(longMsg);
    assertThat(out).hasSize(BlockReasonProperty.MAX_STORED_LENGTH);
    assertThat(out).endsWith("...");
  }
}
