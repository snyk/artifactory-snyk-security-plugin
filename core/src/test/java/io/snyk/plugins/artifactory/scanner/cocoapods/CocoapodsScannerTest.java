package io.snyk.plugins.artifactory.scanner.cocoapods;

import io.snyk.plugins.artifactory.model.TestResult;
import io.snyk.plugins.artifactory.scanner.purl.PurlScanner;
import io.snyk.plugins.artifactory.util.SnykConfigForTests;
import io.snyk.sdk.SnykConfig;
import io.snyk.sdk.api.SnykClient;
import io.snyk.sdk.model.Severity;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CocoapodsScannerTest {
  CocoapodsScanner scanner;

  RepoPath repoPath;
  FileLayoutInfo fileLayoutInfo;

  @BeforeEach
  void setUp() throws Exception {
    String org = System.getenv("TEST_SNYK_ORG");
    Assertions.assertNotNull(org, "must not be null for test");

    SnykConfig config = SnykConfigForTests.withDefaults();

    SnykClient snykClient = new SnykClient(config);
    scanner = new CocoapodsScanner(new PurlScanner(snykClient, org));

    repoPath = mock(RepoPath.class);
    fileLayoutInfo = mock(FileLayoutInfo.class);
  }

  @Test
  void whenAValidPackage() {
    when(repoPath.getName()).thenReturn("OpenSSL-1.0.2.tar.gz");
    when(repoPath.getPath()).thenReturn("OpenSSL/OpenSSL/tags/1.0.2/OpenSSL-1.0.2.tar.gz");

    TestResult result = scanner.scan(fileLayoutInfo, repoPath);
    assertThat(result.getVulnSummary().getCountAtOrAbove(Severity.MEDIUM))
      .isGreaterThanOrEqualTo(63)
      .withFailMessage("As of 2025-10-03 OpenSSL@1.0.2 should have at least 63 medium+ vulns");
    assertThat(result.getDetailsUrl().toString()).isEqualTo("https://security.snyk.io/package/cocoapods/OpenSSL/1.0.2");
  }
}
