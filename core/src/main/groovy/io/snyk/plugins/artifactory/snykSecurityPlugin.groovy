package io.snyk.plugins.artifactory

import groovy.transform.Field
import io.snyk.plugins.artifactory.core.SnykPlugin
import org.artifactory.repo.RepoPath
import org.artifactory.request.Request

@Field SnykPlugin snykPlugin

initialize()

download {
  beforeDownload { Request request, RepoPath repoPath ->
    snykPlugin.handleBeforeDownloadEvent(repoPath)
  }
}

private void initialize() {
  log.info("Initializing snykSecurityPlugin...")

  final File pluginsDirectory = ctx.artifactoryHome.pluginsDir
  snykPlugin = new SnykPlugin(repositories, pluginsDirectory)

  log.info("Initialization of snykSecurityPlugin completed")
}
