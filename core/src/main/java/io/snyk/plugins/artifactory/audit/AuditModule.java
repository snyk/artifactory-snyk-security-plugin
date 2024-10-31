package io.snyk.plugins.artifactory.audit;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.artifactory.fs.ItemInfo;
import org.artifactory.security.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static io.snyk.plugins.artifactory.configuration.properties.ArtifactProperty.ISSUE_LICENSES_FORCE_DOWNLOAD;
import static io.snyk.plugins.artifactory.configuration.properties.ArtifactProperty.ISSUE_LICENSES_FORCE_DOWNLOAD_INFO;
import static io.snyk.plugins.artifactory.configuration.properties.ArtifactProperty.ISSUE_VULNERABILITIES_FORCE_DOWNLOAD;
import static io.snyk.plugins.artifactory.configuration.properties.ArtifactProperty.ISSUE_VULNERABILITIES_FORCE_DOWNLOAD_INFO;

public class AuditModule {

  private static final Logger LOG = LoggerFactory.getLogger(AuditModule.class);

  public AuditModule() {
    //squid:S1186
  }

  public void logPropertyUpdate(@Nullable User user, @Nonnull ItemInfo itemInfo, String propertyName, String[] propertyValues) {
    if (propertyName == null || !propertyIsRelevant(propertyName)) {
      return;
    }

    String username = "";
    if (user == null) {
      LOG.warn("No authentication details are present for current user!");
    } else {
      username = user.getUsername() + "/" + user.getLastLoginClientIp();
    }

    LOG.info("Artifact: '{}'. User '{}' updated property '{}' with value '{}'.", itemInfo.getRepoPath(), username, propertyName, propertyValues);
  }

  private boolean propertyIsRelevant(@Nonnull String propertyName) {
    return ISSUE_LICENSES_FORCE_DOWNLOAD.propertyKey().equals(propertyName) ||
      ISSUE_LICENSES_FORCE_DOWNLOAD_INFO.propertyKey().equals(propertyName) ||
      ISSUE_VULNERABILITIES_FORCE_DOWNLOAD.propertyKey().equals(propertyName) ||
      ISSUE_VULNERABILITIES_FORCE_DOWNLOAD_INFO.propertyKey().equals(propertyName);
  }
}
