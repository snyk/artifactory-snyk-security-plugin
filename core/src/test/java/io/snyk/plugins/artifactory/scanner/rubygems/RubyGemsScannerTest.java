package io.snyk.plugins.artifactory.scanner.rubygems;

import io.snyk.plugins.artifactory.exception.CannotScanException;
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

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RubyGemsScannerTest {

  RubyGemsScanner scanner;

  RepoPath repoPath;
  FileLayoutInfo fileLayoutInfo;

  @BeforeEach
  void setUp() throws Exception {
    String org = System.getenv("TEST_SNYK_ORG");
    Assertions.assertNotNull(org, "must not be null for test");

    SnykConfig config = SnykConfigForTests.withDefaults();

    SnykClient snykClient = new SnykClient(config);
    scanner = new RubyGemsScanner(new PurlScanner(snykClient, org));

    repoPath = mock(RepoPath.class);
    fileLayoutInfo = mock(FileLayoutInfo.class);
  }

  @Test
  void whenAValidGemPackage() {
    when(repoPath.getName()).thenReturn("sinatra-2.0.0.gem");

    TestResult result = scanner.scan(fileLayoutInfo, repoPath);
    assertThat(result.getVulnSummary().getCountAtOrAbove(Severity.MEDIUM)).isGreaterThanOrEqualTo(5);
    assertThat(result.getDetailsUrl().toString()).isEqualTo("https://security.snyk.io/package/rubygems/sinatra/2.0.0");
  }

  @Test
  void whenNotAGem() {
    when(repoPath.getName()).thenReturn("sinatra");

    assertThatThrownBy(() -> scanner.scan(fileLayoutInfo, repoPath))
      .isExactlyInstanceOf(CannotScanException.class)
      .hasMessageContaining("sinatra");
  }

  @Test
  void whenUnexpectedPackageNameStructure() {
    when(repoPath.getName()).thenReturn("version.missing.gem");

    assertThatThrownBy(() -> scanner.scan(fileLayoutInfo, repoPath))
      .isExactlyInstanceOf(CannotScanException.class)
        .hasMessageContaining("version.missing.gem");
  }
}
