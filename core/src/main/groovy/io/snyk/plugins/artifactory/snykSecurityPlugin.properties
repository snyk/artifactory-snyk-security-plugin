# =====================================
# Snyk Artifactory Plugin Configuration
# =====================================
# Scan your Artifacts for security issues.
# Documentation: https://support.snyk.io/hc/en-us/articles/360004032417-Artifactory-Gatekeeper-plugin-overview

# =================
# API Configuration
# =================

# Your Snyk API Token for authentication.
# You can find this under your Account's Settings.
# Required.
snyk.api.token=

# Your Snyk Organization ID.
# You can find this under your Organisation's Settings.
# Required.
snyk.api.organization=

# The base URL for all Snyk API endpoints.
# Documentation: https://snyk.docs.apiary.io/#introduction/api-url
# Default: https://snyk.io/api/v1/
#snyk.api.url=https://snyk.io/api/v1/

# Path to an SSL Certificate for Snyk API in PEM format.
#snyk.api.sslCertificatePath=

# If you are using a proxy, you must provide both Hostname/IP and port.
#snyk.http.proxyHost=
#snyk.http.proxyPort=

# If set to "true", automatically trusts all certificates used by Snyk API.
# Accepts: "true", "false"
# Default: "false"
#snyk.api.trustAllCertificates=false

# By default, if Snyk API hasn't responded within a duration of 60 seconds, the request will be cancelled.
# This property lets you customise the timeout duration in milliseconds.
# Default: "60000"
#snyk.api.timeout=60000

# =====================
# Scanner Configuration
# =====================

# By default, if Snyk API fails while scanning an artifact for any reason, the download will be allowed.
# Setting this property to "true" will block downloads when Snyk API fails.
# Accepts: "true", "false"
# Default: "false"
#snyk.scanner.block-on-api-failure=false

# Global threshold for vulnerability issues.
# Accepts: "none", "low", "medium", "high", "critical"
# Default: "low"
#snyk.scanner.vulnerability.threshold=low

# Global threshold for license issues.
# Accepts: "none", "low", "medium", "high"
# Default: "low"
#snyk.scanner.license.threshold=low

# Scan Maven repositories.
# Accepts: "true", "false"
# Default: "true"
#snyk.scanner.packageType.maven=true

# Scan npm repositories.
# Accepts: "true", "false"
# Default: "true"
#snyk.scanner.packageType.npm=true

# Scan PyPi repositories.
# Accepts: "true", "false"
# Default: "false"
#snyk.scanner.packageType.pypi=false
