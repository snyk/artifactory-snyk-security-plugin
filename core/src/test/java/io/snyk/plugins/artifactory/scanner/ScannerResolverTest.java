package io.snyk.plugins.artifactory.scanner;

import io.snyk.plugins.artifactory.model.IssueSummary;
import io.snyk.plugins.artifactory.model.TestResult;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.stream.Stream;

import static io.snyk.plugins.artifactory.ecosystem.Ecosystem.MAVEN;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

class ScannerResolverTest {

  @Test
  void scannerEnabled() {
    ScannerResolver resolver = new ScannerResolver((param) -> "true")
      .register(MAVEN, new DummyScanner());

    assertThat(resolver.getFor(MAVEN)).isPresent();
  }

  @Test
  void scannerDisabled() {
    ScannerResolver resolver = new ScannerResolver((param) -> "false")
      .register(MAVEN, new DummyScanner());

    assertThat(resolver.getFor(MAVEN)).isEmpty();
  }

  @Test
  void scannerNotRegistered() {
    ScannerResolver resolver = new ScannerResolver((param) -> "true");

    assertThat(resolver.getFor(MAVEN)).isEmpty();
  }

  static class DummyScanner implements PackageScanner {

    @Override
    public TestResult scan(FileLayoutInfo fileLayoutInfo, RepoPath repoPath) {
      return new TestResult(
        IssueSummary.from(Stream.empty()),
        IssueSummary.from(Stream.empty()),
        URI.create("https://snyk.io")
      );
    }
  }
}
