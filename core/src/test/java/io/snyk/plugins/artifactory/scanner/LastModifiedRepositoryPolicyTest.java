package io.snyk.plugins.artifactory.scanner;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LastModifiedRepositoryPolicyTest {

  @Test
  void parseAllowlist_nullOrBlank_returnsEmpty() {
    assertTrue(LastModifiedRepositoryPolicy.parseAllowlist(null).isEmpty());
    assertTrue(LastModifiedRepositoryPolicy.parseAllowlist("").isEmpty());
    assertTrue(LastModifiedRepositoryPolicy.parseAllowlist("   ").isEmpty());
    assertTrue(LastModifiedRepositoryPolicy.parseAllowlist(" , , ").isEmpty());
  }

  @Test
  void parseAllowlist_splitsTrimsAndDropsEmptySegments() {
    assertEquals(List.of("a", "b"), LastModifiedRepositoryPolicy.parseAllowlist("a,b"));
    assertEquals(List.of("x", "y"), LastModifiedRepositoryPolicy.parseAllowlist(" x , y "));
    assertEquals(List.of("one"), LastModifiedRepositoryPolicy.parseAllowlist("one,,,"));
  }

  @Test
  void repoKeyMatchesAllowlist_substringMatch() {
    List<String> patterns = List.of("-local", "cache");
    assertTrue(LastModifiedRepositoryPolicy.repoKeyMatchesAllowlist("npm-local", patterns));
    assertTrue(LastModifiedRepositoryPolicy.repoKeyMatchesAllowlist("maven-cache-remote", patterns));
    assertFalse(LastModifiedRepositoryPolicy.repoKeyMatchesAllowlist("npm-remote", patterns));
  }

  @Test
  void repoKeyMatchesAllowlist_emptyPatterns_neverMatches() {
    assertFalse(LastModifiedRepositoryPolicy.repoKeyMatchesAllowlist("anything", List.of()));
  }
}
