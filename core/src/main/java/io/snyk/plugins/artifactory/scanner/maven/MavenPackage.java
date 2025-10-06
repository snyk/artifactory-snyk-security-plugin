package io.snyk.plugins.artifactory.scanner.maven;

import org.artifactory.fs.FileLayoutInfo;
import org.slf4j.Logger;

import java.util.Optional;

import static org.slf4j.LoggerFactory.getLogger;

public class MavenPackage {
  private static final Logger LOG = getLogger(MavenPackage.class);
  private final String groupID;
  private final String artifactID;
  private final String version;

  public MavenPackage(String groupID, String artifactID, String version) {
    this.groupID = groupID;
    this.artifactID = artifactID;
    this.version = version;
  }

  public String getGroupID() {
    return groupID;
  }

  public String getArtifactID() {
    return artifactID;
  }

  public String getName() {
    return groupID + "/" + artifactID;
  }

  public String getVersion() {
    return version;
  }

  public static Optional<MavenPackage> parse(FileLayoutInfo fileLayoutInfo) {
    String groupID = fileLayoutInfo.getOrganization();
    String artifactID = fileLayoutInfo.getModule();
    String version = fileLayoutInfo.getBaseRevision();

    if (groupID == null || artifactID == null || version == null) {
      LOG.warn("Maven package details not provided in FileLayoutInfo");
      return Optional.empty();
    }

    return Optional.of(new MavenPackage(groupID, artifactID, version));
  }
}
