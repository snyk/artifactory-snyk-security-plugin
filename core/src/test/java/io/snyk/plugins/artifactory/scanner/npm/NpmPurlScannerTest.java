package io.snyk.plugins.artifactory.scanner.npm;

import io.snyk.plugins.artifactory.exception.CannotScanException;
import io.snyk.plugins.artifactory.model.TestResult;
import io.snyk.plugins.artifactory.scanner.purl.PurlScanner;
import io.snyk.plugins.artifactory.util.SnykConfigForTests;
import io.snyk.sdk.SnykConfig;
import io.snyk.sdk.api.SnykClient;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class NpmPurlScannerTest {

  NpmPurlScanner scanner;

  RepoPath repoPath;
  FileLayoutInfo fileLayoutInfo;

  @BeforeEach
  void setUp() throws Exception {
    String org = System.getenv("TEST_SNYK_ORG");
    Assertions.assertNotNull(org, "must not be null for test");

    SnykConfig config = SnykConfigForTests.withDefaults();

    SnykClient snykClient = new SnykClient(config);
    scanner = new NpmPurlScanner(new PurlScanner(snykClient, org));

    repoPath = mock(RepoPath.class);
    fileLayoutInfo = mock(FileLayoutInfo.class);
  }

  @Test
  void whenAValidNpmPackage() {
    when(repoPath.toString()).thenReturn("npm:lodash/-/lodash-4.17.15.tgz");

    TestResult result = scanner.scan(fileLayoutInfo, repoPath);
    assertThat(result.getVulnSummary().getTotalCount()).isGreaterThanOrEqualTo(5)
      .withFailMessage("As of 2025-10-03 lodash@4.17.15 should have at least 5 vulns");
    assertThat(result.getDetailsUrl().toString()).isEqualTo("https://security.snyk.io/package/npm/lodash/4.17.15");
  }

  @Test
  void whenAValidNpmPackageWithScope() {
    when(repoPath.toString()).thenReturn("npm:@snyk/protect/-/protect-1.675.0.tgz");

    TestResult result = scanner.scan(fileLayoutInfo, repoPath);
    assertThat(result.getVulnSummary().getTotalCount()).isGreaterThanOrEqualTo(0)
      .withFailMessage("@snyk/protect@1.675.0 scan should complete successfully");
    assertThat(result.getDetailsUrl().toString()).isEqualTo("https://security.snyk.io/package/npm/%40snyk%2Fprotect/1.675.0");
  }

  @Test
  void whenInvalidPackagePath() {
    when(repoPath.toString()).thenReturn("invalid-path");

    assertThatThrownBy(() -> scanner.scan(fileLayoutInfo, repoPath))
      .isExactlyInstanceOf(CannotScanException.class)
      .hasMessageContaining("Package details not provided");
  }

  @Test
  void getPackageDetailsURL_shouldEncodeNameAndVersion() {
    NpmPackage pckg = new NpmPackage("@babel/core", "7.0.0-rc.4");
    String result = NpmPurlScanner.getPackageDetailsURL(pckg);
    assertThat(result).isEqualTo("https://security.snyk.io/package/npm/%40babel%2Fcore/7.0.0-rc.4");
  }
}

