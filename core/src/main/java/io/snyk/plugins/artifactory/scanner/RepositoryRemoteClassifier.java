package io.snyk.plugins.artifactory.scanner;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Classifies whether a repository is treated as remote for last-modified checks, combining optional
 * substring matching on the repository key with Artifactory's configured repository type.
 */
public final class RepositoryRemoteClassifier {

  private RepositoryRemoteClassifier() {}

  static List<String> parseCommaSeparatedPatterns(String raw) {
    if (raw == null || raw.isBlank()) {
      return List.of();
    }
    List<String> lowered = new ArrayList<>();
    for (String part : raw.split(",")) {
      String trimmed = part.trim();
      if (!trimmed.isEmpty()) {
        lowered.add(trimmed.toLowerCase(Locale.ROOT));
      }
    }
    return Collections.unmodifiableList(lowered);
  }

  /**
   * @return true if {@code repoKey} contains any of the patterns (case-insensitive substring match).
   */
  static boolean repoKeyContainsAnyPattern(String repoKey, List<String> patternsLowercase) {
    if (repoKey == null || patternsLowercase.isEmpty()) {
      return false;
    }
    String keyLower = repoKey.toLowerCase(Locale.ROOT);
    for (String pattern : patternsLowercase) {
      if (keyLower.contains(pattern)) {
        return true;
      }
    }
    return false;
  }

  /**
   * When local name matching is enabled and a pattern matches, the repository is not treated as remote.
   * Otherwise {@code artifactoryTypeIsRemote} is used.
   */
  static boolean isRemoteRepository(
    String repoKey,
    boolean localNameMatchEnabled,
    String patternsRaw,
    boolean artifactoryTypeIsRemote
  ) {
    if (localNameMatchEnabled) {
      List<String> patterns = parseCommaSeparatedPatterns(patternsRaw);
      if (!patterns.isEmpty() && repoKeyContainsAnyPattern(repoKey, patterns)) {
        return false;
      }
    }
    return artifactoryTypeIsRemote;
  }
}
