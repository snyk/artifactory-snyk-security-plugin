package io.snyk.plugins.artifactory.scanner;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("RepositoryRemoteClassifier")
class RepositoryRemoteClassifierTest {

  @DisplayName("parseCommaSeparatedPatterns trims, ignores empties, lowercases")
  @Test
  void parseCommaSeparatedPatterns() {
    assertAll(
      () -> assertTrue(RepositoryRemoteClassifier.parseCommaSeparatedPatterns("").isEmpty()),
      () -> assertTrue(RepositoryRemoteClassifier.parseCommaSeparatedPatterns("  ,  ").isEmpty()),
      () -> assertEquals(
        List.of("a", "bc"),
        RepositoryRemoteClassifier.parseCommaSeparatedPatterns(" a , bc ")
      ),
      () -> assertEquals(
        List.of("libs-release", "internal"),
        RepositoryRemoteClassifier.parseCommaSeparatedPatterns("Libs-Release, INTERNAL")
      )
    );
  }

  @DisplayName("repoKeyContainsAnyPattern is case-insensitive substring match")
  @Test
  void repoKeyContainsAnyPattern() {
    List<String> p = List.of("remote", "cache");
    assertAll(
      () -> assertFalse(RepositoryRemoteClassifier.repoKeyContainsAnyPattern(null, p)),
      () -> assertFalse(RepositoryRemoteClassifier.repoKeyContainsAnyPattern("my-local", List.of())),
      () -> assertTrue(RepositoryRemoteClassifier.repoKeyContainsAnyPattern("MY-REMOTE-REPO", p)),
      () -> assertTrue(RepositoryRemoteClassifier.repoKeyContainsAnyPattern("pypi-cache", p)),
      () -> assertFalse(RepositoryRemoteClassifier.repoKeyContainsAnyPattern("clean", p))
    );
  }

  @DisplayName("isRemoteRepository: feature off uses Artifactory type only")
  @Test
  void featureOffUsesArtifactoryOnly() {
    assertTrue(RepositoryRemoteClassifier.isRemoteRepository("any", false, "local", true));
    assertFalse(RepositoryRemoteClassifier.isRemoteRepository("any", false, "local", false));
  }

  @DisplayName("isRemoteRepository: enabled with empty patterns falls back to Artifactory type")
  @Test
  void enabledEmptyPatternsFallsBack() {
    assertTrue(RepositoryRemoteClassifier.isRemoteRepository("my-local", true, "", true));
    assertFalse(RepositoryRemoteClassifier.isRemoteRepository("my-local", true, " , ", false));
  }

  @DisplayName("isRemoteRepository: pattern match forces non-remote")
  @Test
  void patternMatchForcesLocal() {
    assertFalse(RepositoryRemoteClassifier.isRemoteRepository("company-local-repo", true, "local", true));
  }

  @DisplayName("isRemoteRepository: no pattern match falls back to Artifactory type")
  @Test
  void noPatternMatchFallsBack() {
    assertTrue(RepositoryRemoteClassifier.isRemoteRepository("remote-npm", true, "local-only", true));
    assertFalse(RepositoryRemoteClassifier.isRemoteRepository("remote-npm", true, "local-only", false));
  }
}
