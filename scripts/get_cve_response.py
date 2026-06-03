#!/usr/bin/env python3
"""Scenario 3 — CVE list from an existing CycloneDX SBOM (wrapper for ``vex4edk2-cve-scan``).

See README § Component CVE sourcing (NVD vs Grype) for ``--scanner``, ``NVD_API_KEY``, and Grype setup.
"""

from vex4edk2.cve_scan import main

if __name__ == "__main__":
    main()
