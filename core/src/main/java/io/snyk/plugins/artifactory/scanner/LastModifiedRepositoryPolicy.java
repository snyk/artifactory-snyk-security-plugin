package io.snyk.plugins.artifactory.scanner;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Parses {@link io.snyk.plugins.artifactory.configuration.PluginConfiguration#SCANNER_LAST_MODIFIED_ALLOWLIST}
 * and decides whether a repository key matches any allowlisted substring.
 */
final class LastModifiedRepositoryPolicy {

  private LastModifiedRepositoryPolicy() {}

  static List<String> parseAllowlist(String raw) {
    if (raw == null || raw.isBlank()) {
      return List.of();
    }
    List<String> out = new ArrayList<>();
    for (String segment : raw.split(",")) {
      String t = segment.trim();
      if (!t.isEmpty()) {
        out.add(t);
      }
    }
    return out.isEmpty() ? List.of() : Collections.unmodifiableList(out);
  }

  static boolean repoKeyMatchesAllowlist(String repoKey, List<String> substrings) {
    for (String s : substrings) {
      if (repoKey.contains(s)) {
        return true;
      }
    }
    return false;
  }
}
