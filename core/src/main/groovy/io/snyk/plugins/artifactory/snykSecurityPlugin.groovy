package io.snyk.plugins.artifactory

import groovy.transform.Field
import org.artifactory.repo.RepoPath
import org.artifactory.request.Request

@Field SnykPlugin snykPlugin

initialize()

private void initialize() {
  log.info("Initializing snykSecurityPlugin...")

  final File pluginsDirectory = ctx.artifactoryHome.pluginsDir
  snykPlugin = new SnykPlugin(repositories, pluginsDirectory)

  log.info("Initialization of snykSecurityPlugin completed")
}

executions {
  snykSecurityReload(httpMethod: "POST") { params ->
    initialize()
  }
}

download {
  beforeDownload { Request request, RepoPath repoPath ->
    snykPlugin.handleBeforeDownloadEvent(repoPath)
  }
}
