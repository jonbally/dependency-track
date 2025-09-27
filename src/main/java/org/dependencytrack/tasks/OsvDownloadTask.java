/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.tasks;

import alpine.Config;
import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.LoggableSubscriber;
import alpine.model.ConfigProperty;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.util.EntityUtils;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.event.OsvMirrorEvent;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.model.VulnerableSoftware;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.parser.osv.OsvAdvisoryParser;
import org.dependencytrack.parser.osv.model.OsvAdvisory;
import org.dependencytrack.parser.osv.model.OsvAffectedPackage;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.CvssUtil;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.slf4j.MDC;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.BufferedInputStream;
import java.io.File;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Scanner;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static org.dependencytrack.common.MdcKeys.MDC_VULN_ID;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ALIAS_SYNC_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED;
import static org.dependencytrack.model.Severity.getSeverityByLevel;
import static org.dependencytrack.util.VulnerabilityUtil.normalizedCvssV2Score;
import static org.dependencytrack.util.VulnerabilityUtil.normalizedCvssV3Score;

public class OsvDownloadTask implements LoggableSubscriber {

    public static final Path DEFAULT_OSV_MIRROR_DIR = Config.getInstance().getDataDirectorty().toPath().resolve("osv").toAbsolutePath();
    private static final long MAX_ZIP_BYTES = 500L * 1024 * 1024; // Max size for zip files 500 MiB

    private static final Logger LOGGER = Logger.getLogger(OsvDownloadTask.class);
    private Set<String> ecosystems;
    private String osvBaseUrl;
    private File outputDir;
    private final Path mirrorDirPath;
    private boolean aliasSyncEnabled;
    private long metricParseTime;
    private long metricDownloadTime;

    public OsvDownloadTask() {
        this(DEFAULT_OSV_MIRROR_DIR);
    }

    OsvDownloadTask(final Path mirrorDirPath) {
        this.mirrorDirPath = mirrorDirPath;
        try (final QueryManager qm = new QueryManager()) {
            final ConfigProperty enabled = qm.getConfigProperty(VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED.getGroupName(), VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED.getPropertyName());
            if (enabled != null) {
                final String ecosystemConfig = enabled.getPropertyValue();
                if (ecosystemConfig != null) {
                    ecosystems = Arrays.stream(ecosystemConfig.split(";")).map(String::trim).collect(Collectors.toSet());
                }
                this.osvBaseUrl = qm.getConfigProperty(VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL.getGroupName(), VULNERABILITY_SOURCE_GOOGLE_OSV_BASE_URL.getPropertyName()).getPropertyValue();
                if (this.osvBaseUrl != null && !this.osvBaseUrl.endsWith("/")) {
                    this.osvBaseUrl += "/";
                }
                final ConfigProperty aliasSyncProperty = qm.getConfigProperty(
                        VULNERABILITY_SOURCE_GOOGLE_OSV_ALIAS_SYNC_ENABLED.getGroupName(),
                        VULNERABILITY_SOURCE_GOOGLE_OSV_ALIAS_SYNC_ENABLED.getPropertyName()
                );
                if (aliasSyncProperty != null) {
                    this.aliasSyncEnabled = "true".equals(aliasSyncProperty.getPropertyValue());
                }
            }
        }
    }

    @Override
    public void inform(Event e) {
        if (e instanceof OsvMirrorEvent) {
            if (ecosystems == null || ecosystems.isEmpty()) {
                LOGGER.info("Google OSV mirroring is disabled. No ecosystem selected.");
                return;
            }
            final long start = System.currentTimeMillis();
            setOutputDir(mirrorDirPath.toAbsolutePath().toString());
            ecosystems.forEach(this::processOsvEcosystem);
            final long end = System.currentTimeMillis();
            LOGGER.info("Google OSV mirroring complete");
            LOGGER.info("Time spent (d/l):   " + metricDownloadTime + " ms");
            LOGGER.info("Time spent (parse): " + metricParseTime + " ms");
            LOGGER.info("Time spent (total): " + (end - start) + " ms");
        }
    }

    private void processOsvEcosystem(String ecosystem) {
        try (var ignoredMdcOsvEcosystem = MDC.putCloseable("osvEcosystem", ecosystem)) {
            if (shouldDoIncrementalUpdate(ecosystem)) {
                String url = this.osvBaseUrl + URLEncoder.encode(ecosystem, StandardCharsets.UTF_8).replace("+", "%20")
                        + "/modified_id.csv";
                LOGGER.info("Initiating download of " + url);
                final long downloadStart = System.currentTimeMillis();
                Path modifiedCsv = downloadModifiedCsvFile(url, ecosystem);
                if (modifiedCsv != null) {
                    LOGGER.debug("Downloaded list of modified OSV advisories for " +  ecosystem + " into " + modifiedCsv);
                    final long downloadEnd = System.currentTimeMillis();
                    metricDownloadTime += downloadEnd - downloadStart;
                    processModifiedCsvFile(modifiedCsv, ecosystem);
                }
            } else {
                String url = this.osvBaseUrl + URLEncoder.encode(ecosystem, StandardCharsets.UTF_8).replace("+", "%20")
                        + "/all.zip";
                LOGGER.info("Initiating download of " + url);
                final long downloadStart = System.currentTimeMillis();
                Path osvZipFile = downloadOsvZipFile(url, ecosystem);
                if (osvZipFile != null) {
                    LOGGER.debug("Downloaded OSV advisories for " +  ecosystem + " into " + osvZipFile);
                    final long downloadEnd = System.currentTimeMillis();
                    metricDownloadTime += downloadEnd - downloadStart;
                    processOsvZipFile(osvZipFile);
                }
            }
        } catch (Exception ex) {
            LOGGER.error("Exception while downloading/unzipping OSV data for " + ecosystem, ex);
        }
    }

    private boolean shouldDoIncrementalUpdate(String ecosystem) {
        // Check if the file to get (for the ecosystem) already exists in the dir
        // If it exists then check if a corresponding .ts file for this file exists
        // If it exists then open and parse the timestamp file to retrieve the timestamp
        // If the timestamp of modification plus the interval (5 days for now) is greater than current timestamp,
        // then return true, else false
        return true;
    }

    private long getContentLength(final String osvUrl) {
        final HttpUriRequest request = new HttpHead(osvUrl);
        try (final CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
            return Long.parseLong(response.getFirstHeader(HttpHeaders.CONTENT_LENGTH).getValue());
        } catch (IOException | NumberFormatException | NullPointerException e) {
            LOGGER.error("Failed to determine content length");
        }
        return 0;
    }

    private Path downloadModifiedCsvFile(String url, String ecosystem) throws IOException {
        final HttpUriRequest request = new HttpGet(url);
        try (CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
            final StatusLine status = response.getStatusLine();
            final HttpEntity entity = response.getEntity();
            try {
                LOGGER.info("Downloading...");
                if (status.getStatusCode() != HttpStatus.SC_OK) {
                    LOGGER.error("Download of modified_id.csv failed for: " + ecosystem + " - " +
                            status.getStatusCode() + " " + status.getReasonPhrase());
                    return null;
                }
                // TODO: change download to outputDir instead of temp file
                //  also create the timestamp file for the downloaded file
                final Path tempFile = Files.createTempFile("google-osv-modified-" + ecosystem + "-", ".csv");
                try (final InputStream in = response.getEntity().getContent()) {
                    Files.copy(in, tempFile.toAbsolutePath(), StandardCopyOption.REPLACE_EXISTING);
                    return tempFile.toAbsolutePath();
                }
            } finally {
                EntityUtils.consumeQuietly(entity);
            }
        }
    }

    private void processModifiedCsvFile(Path modifiedCsvFilePath, String ecosystem) throws IOException {
        final long start = System.currentTimeMillis();
        if (Files.size(modifiedCsvFilePath) <= 0) {
            LOGGER.warn("Modified CSV file is empty, skipping and deleting: " + modifiedCsvFilePath.getFileName());
            Files.delete(modifiedCsvFilePath);
            return;
        }
        LOGGER.info("Parsing OSV advisory JSON files in " + modifiedCsvFilePath.getFileName());
        Instant lastUpdate = Instant.parse("2025-09-24T23:41:23.279728Z"); // TODO: remove and replace with actual last update
        // TODO: Problem - some modified_id.csv files, e.g. Debian, contain a lot of modified entries within a short time
        //  this could be handled in a few ways, such as limiting incremental updates to 1000 or less advisories or batching
        ArrayList<JSONObject> modifiedOsvAdvisories = downloadModifiedOsvAdvisories(modifiedCsvFilePath, lastUpdate, ecosystem);
        assert modifiedOsvAdvisories != null;
        modifiedOsvAdvisories.forEach(this::processOsvAdvisoryJsonFromCsv);
        final long end = System.currentTimeMillis();
        metricParseTime += end - start;
    }

    private ArrayList<JSONObject> downloadModifiedOsvAdvisories(Path modifiedCsvFilePath, Instant lastUpdate, String ecosystem) throws IOException {
        ArrayList<String> modifiedIds = new ArrayList<>();
        try (BufferedReader reader = Files.newBufferedReader(modifiedCsvFilePath)) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) {
                    continue;
                }
                String[] parts = line.split(",", 2);
                if (parts.length != 2) {
                    continue;
                }
                String timestampStr = parts[0].trim();
                String id = parts[1].trim();
                try {
                    Instant currentTimestamp = Instant.parse(timestampStr);
                    if (lastUpdate != null && currentTimestamp.isBefore(lastUpdate)) {
                        break;
                    }
                    modifiedIds.add(id);
                    LOGGER.info("ID added: " + id);
                } catch (DateTimeParseException e) {
                    System.err.println("Skipping line with invalid timestamp: " + line);
                }
            }
        }
        ArrayList<JSONObject> modifiedAdvisoriesJson = new ArrayList<>();
        for (String id : modifiedIds) {
            String url = this.osvBaseUrl + URLEncoder.encode(ecosystem, StandardCharsets.UTF_8).replace("+", "%20")
                    + "/" + id + ".json";
            final HttpUriRequest request = new HttpGet(url);
            try (CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
                final StatusLine status = response.getStatusLine();
                final HttpEntity entity = response.getEntity();
                try {
                    if (status.getStatusCode() != HttpStatus.SC_OK) {
                        LOGGER.error("Download of advisory file failed for: " + id + " - " +
                                status.getStatusCode() + " " + status.getReasonPhrase());
                        return null;
                    }
                    try (final InputStream in = response.getEntity().getContent()) {
                        final BufferedReader reader = new BufferedReader(
                                new InputStreamReader(in, StandardCharsets.UTF_8), 8192
                        );
                        LOGGER.info("Downloaded: " + url);
                        final JSONObject json = new JSONObject(new JSONTokener(reader));
                        modifiedAdvisoriesJson.add(json);
                    }
                } finally {
                    EntityUtils.consumeQuietly(entity);
                }
            }
        }
        return modifiedAdvisoriesJson;
    }

    private void processOsvAdvisoryJsonFromCsv(JSONObject modifiedOsvAdvisory) {
        final OsvAdvisoryParser parser = new OsvAdvisoryParser();
        try {
            final String advisoryId = modifiedOsvAdvisory.optString("id", "unknown");
            try (var ignoredMdcVulnId = MDC.putCloseable(MDC_VULN_ID, advisoryId)) {
                final OsvAdvisory osvAdvisory = parser.parse(modifiedOsvAdvisory);
                if (osvAdvisory != null) {
                    updateDatasource(osvAdvisory);
                    LOGGER.info("Successfully processed advisory: " + advisoryId);
                } else {
                    LOGGER.debug("Advisory: " + advisoryId + " was not processed further (withdrawn or parsing error)");
                }
            }
        } catch (RuntimeException e) {
            LOGGER.error("Unexpected error processing modified OSV advisory: ", e);
        }
    }

    private Path downloadOsvZipFile(String url, String ecosystem) throws IOException {
        final HttpUriRequest request = new HttpGet(url);
        try (CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
            final StatusLine status = response.getStatusLine();
            final HttpEntity entity = response.getEntity();
            try {
                LOGGER.info("Downloading...");
                if (status.getStatusCode() != HttpStatus.SC_OK) {
                    LOGGER.error("Download of all.zip failed for: " + ecosystem + " - " +
                            status.getStatusCode() + " " + status.getReasonPhrase());
                    return null;
                }
                long contentLength = entity.getContentLength();
                LOGGER.debug("HTTP contentLength for " + ecosystem + ": " + contentLength);
                if (contentLength > MAX_ZIP_BYTES) {
                    throw new IOException(
                            String.format("ZIP too large for ecosystem %s: %d bytes (limit %d)",
                                    ecosystem, contentLength, MAX_ZIP_BYTES));
                }
                // TODO: change download dir and do not download temp file
                //  also create the timestamp file for the downloaded file
                final Path tempFile = Files.createTempFile("google-osv-download-" + ecosystem + "-", ".zip");
                try (final InputStream in = response.getEntity().getContent()) {
                    Files.copy(in, tempFile.toAbsolutePath(), StandardCopyOption.REPLACE_EXISTING);
                    return tempFile.toAbsolutePath();
                }
            } finally {
                EntityUtils.consumeQuietly(entity);
            }
        }
    }

    private void processOsvZipFile(Path tempFile) throws IOException {
        final long start = System.currentTimeMillis();
        if (Files.size(tempFile) <= 0) {
            LOGGER.warn("Temporary OSV file is empty, skipping and deleting: " + tempFile.getFileName());
            Files.delete(tempFile);
            return;
        }
        LOGGER.info("Uncompressing " + tempFile.getFileName());
        try (final var in = Files.newInputStream(tempFile, StandardOpenOption.DELETE_ON_CLOSE);
             final var bufferedIn = new BufferedInputStream(in);
             final var zipInput = new ZipInputStream(bufferedIn)) {
            LOGGER.info("Parsing OSV advisory JSON files in " + tempFile.getFileName());
            unzipOsvZipFile(zipInput);
        }
        final long end = System.currentTimeMillis();
        metricParseTime += end - start;
    }

    private void unzipOsvZipFile(ZipInputStream zipIn) throws IOException {
        final Pattern jsonPattern = Pattern.compile("\\.json$", Pattern.CASE_INSENSITIVE);
        ZipEntry zipEntry;
        while ((zipEntry = zipIn.getNextEntry()) != null) {
            try {
                if (zipEntry.isDirectory()) {
                    LOGGER.warn("Skipped directory: " + zipEntry.getName());
                    continue;
                }
                final String entryName = zipEntry.getName();
                if (!jsonPattern.matcher(entryName).find()) {
                    LOGGER.warn("Skipped non-JSON entry: " + entryName);
                    continue;
                }
                processOsvAdvisoryJsonFromZip(zipIn, entryName);
            } finally {
                zipIn.closeEntry();
            }
        }
    }

    private void processOsvAdvisoryJsonFromZip(ZipInputStream zipIn, String entryName) {
        final OsvAdvisoryParser parser = new OsvAdvisoryParser();
        try {
            final BufferedReader reader = new BufferedReader(
                    new InputStreamReader(zipIn, StandardCharsets.UTF_8), 8192
            );
            final JSONObject json = new JSONObject(new JSONTokener(reader));
            final String advisoryId = json.optString("id", "unknown");
            try (var ignoredMdcVulnId = MDC.putCloseable(MDC_VULN_ID, advisoryId)) {
                final OsvAdvisory osvAdvisory = parser.parse(json);
                if (osvAdvisory != null) {
                    updateDatasource(osvAdvisory);
                    LOGGER.debug("Successfully processed advisory: " + advisoryId + " from entry: " + entryName);
                } else {
                    LOGGER.debug("Advisory from entry: " + entryName + " was not processed further (withdrawn or parsing error)");
                }
            }
        } catch (JSONException e) {
            LOGGER.error("JSON parsing error for entry: " + entryName, e);
        } catch (RuntimeException e) {
            LOGGER.error("Unexpected error processing entry: " + entryName, e);
        }
    }

    private void setOutputDir(final String outputDirPath) {
        outputDir = new File(outputDirPath);
        if (!outputDir.exists()) {
            if (outputDir.mkdirs()) {
                LOGGER.info("Mirrored data directory created successfully");
            }
        }
    }

    public void updateDatasource(final OsvAdvisory advisory) {

        try (QueryManager qm = new QueryManager()) {

            LOGGER.debug("Synchronizing Google OSV advisory: " + advisory.getId());
            final Vulnerability vulnerability = mapAdvisoryToVulnerability(advisory);
            final List<VulnerableSoftware> vsListOld = qm.detach(qm.getVulnerableSoftwareByVulnId(vulnerability.getSource(), vulnerability.getVulnId()));
            final Vulnerability existingVulnerability = qm.getVulnerabilityByVulnId(vulnerability.getSource(), vulnerability.getVulnId());
            final Vulnerability.Source vulnerabilitySource = extractSource(advisory.getId());
            final ConfigPropertyConstants vulnAuthoritativeSourceToggle = switch (vulnerabilitySource) {
                case NVD -> ConfigPropertyConstants.VULNERABILITY_SOURCE_NVD_ENABLED;
                case GITHUB -> ConfigPropertyConstants.VULNERABILITY_SOURCE_GITHUB_ADVISORIES_ENABLED;
                default -> VULNERABILITY_SOURCE_GOOGLE_OSV_ENABLED;
            };
            final boolean vulnAuthoritativeSourceEnabled = Boolean.parseBoolean(qm.getConfigProperty(vulnAuthoritativeSourceToggle.getGroupName(), vulnAuthoritativeSourceToggle.getPropertyName()).getPropertyValue());
            Vulnerability synchronizedVulnerability = existingVulnerability;
            if (shouldUpdateExistingVulnerability(existingVulnerability, vulnerabilitySource, vulnAuthoritativeSourceEnabled)) {
                synchronizedVulnerability  = qm.synchronizeVulnerability(vulnerability, false);
                if (synchronizedVulnerability == null) return; // Exit if nothing to update
            }

            if (aliasSyncEnabled && advisory.getAliases() != null) {
                for (int i = 0; i < advisory.getAliases().size(); i++) {
                    final String alias = advisory.getAliases().get(i);
                    final VulnerabilityAlias vulnerabilityAlias = new VulnerabilityAlias();

                    // OSV will use IDs of other vulnerability databases for its
                    // primary advisory ID (e.g. GHSA-45hx-wfhj-473x). We need to ensure
                    // that we don't falsely report GHSA IDs as stemming from OSV.
                    switch (vulnerabilitySource) {
                        case NVD -> vulnerabilityAlias.setCveId(advisory.getId());
                        case GITHUB -> vulnerabilityAlias.setGhsaId(advisory.getId());
                        default -> vulnerabilityAlias.setOsvId(advisory.getId());
                    }

                    if (alias.startsWith("CVE") && Vulnerability.Source.NVD != vulnerabilitySource) {
                        vulnerabilityAlias.setCveId(alias);
                        qm.synchronizeVulnerabilityAlias(vulnerabilityAlias);
                    } else if (alias.startsWith("GHSA") && Vulnerability.Source.GITHUB != vulnerabilitySource) {
                        vulnerabilityAlias.setGhsaId(alias);
                        qm.synchronizeVulnerabilityAlias(vulnerabilityAlias);
                    }

                    //TODO - OSV supports GSD and DLA/DSA identifiers (possibly others). Determine how to handle.
                }
            }

            List<VulnerableSoftware> vsList = new ArrayList<>();
            for (OsvAffectedPackage osvAffectedPackage : advisory.getAffectedPackages()) {
                VulnerableSoftware vs = mapAffectedPackageToVulnerableSoftware(qm, osvAffectedPackage);
                if (vs != null) {
                    vsList.add(vs);
                }
            }
            qm.persist(vsList);
            qm.updateAffectedVersionAttributions(synchronizedVulnerability, vsList, Vulnerability.Source.OSV);
            vsList = qm.reconcileVulnerableSoftware(synchronizedVulnerability, vsListOld, vsList, Vulnerability.Source.OSV);
            synchronizedVulnerability.setVulnerableSoftware(vsList);
            qm.persist(synchronizedVulnerability);
        }
        Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
    }

    private boolean shouldUpdateExistingVulnerability(Vulnerability existingVulnerability, Vulnerability.Source vulnerabilitySource, boolean vulnAuthoritativeSourceEnabled) {
        return (Vulnerability.Source.OSV == vulnerabilitySource) // Non GHSA nor NVD
                || (existingVulnerability == null) // Vuln is not replicated yet or declared by authoritative source with appropriate state
                || !vulnAuthoritativeSourceEnabled; // Vuln has been replicated but authoritative source is disabled
    }

    public Vulnerability mapAdvisoryToVulnerability(final OsvAdvisory advisory) {

        final Vulnerability vuln = new Vulnerability();
        if(advisory.getId() != null) {
            vuln.setSource(extractSource(advisory.getId()));
        }
        vuln.setVulnId(String.valueOf(advisory.getId()));
        vuln.setTitle(advisory.getSummary());
        vuln.setDescription(advisory.getDetails());
        vuln.setPublished(Date.from(advisory.getPublished().toInstant()));
        vuln.setUpdated(Date.from(advisory.getModified().toInstant()));

        if (advisory.getCredits() != null) {
            vuln.setCredits(String.join(", ", advisory.getCredits()));
        }

        if (advisory.getReferences() != null && !advisory.getReferences().isEmpty()) {
            final StringBuilder sb = new StringBuilder();
            for (String ref : advisory.getReferences()) {
                sb.append("* [").append(ref).append("](").append(ref).append(")\n");
            }
            vuln.setReferences(sb.toString());
        }

        if (advisory.getCweIds() != null) {
            for (int i=0; i<advisory.getCweIds().size(); i++) {
                final Cwe cwe = CweResolver.getInstance().lookup(advisory.getCweIds().get(i));
                if (cwe != null) {
                    vuln.addCwe(cwe);
                }
            }
        }
        vuln.setSeverity(calculateOSVSeverity(advisory));
        vuln.setCvssV2Vector(advisory.getCvssV2Vector());
        vuln.setCvssV3Vector(advisory.getCvssV3Vector());
        return vuln;
    }

    // calculate severity of vulnerability on priority-basis (database, ecosystem)
    public Severity calculateOSVSeverity(OsvAdvisory advisory) {

        // derive from database_specific cvss v3 vector if available
        if(advisory.getCvssV3Vector() != null) {
            var cvss = CvssUtil.parse(advisory.getCvssV3Vector());
            if (cvss != null) {
                var score = cvss.getBakedScores();
                return normalizedCvssV3Score(score.getOverallScore());
            } else {
                LOGGER.warn("Unable to determine severity from CVSSv3 vector: " + advisory.getCvssV3Vector());
            }
        }
        // derive from database_specific cvss v2 vector if available
        if (advisory.getCvssV2Vector() != null) {
            var cvss = CvssUtil.parse(advisory.getCvssV2Vector());
            if (cvss != null) {
                var score = cvss.getBakedScores();
                return normalizedCvssV2Score(score.getOverallScore());
            } else {
                LOGGER.warn("Unable to determine severity from CVSSv2 vector: " + advisory.getCvssV2Vector());
            }
        }
        // get database_specific severity string if available
        if (advisory.getSeverity() != null) {
            if (advisory.getSeverity().equalsIgnoreCase("CRITICAL")) {
                return Severity.CRITICAL;
            } else if (advisory.getSeverity().equalsIgnoreCase("HIGH")) {
                return Severity.HIGH;
            } else if (advisory.getSeverity().equalsIgnoreCase("MODERATE")) {
                return Severity.MEDIUM;
            } else if (advisory.getSeverity().equalsIgnoreCase("LOW")) {
                return Severity.LOW;
            }
        }
        // get largest ecosystem_specific severity from its affected packages
        if (!advisory.getAffectedPackages().isEmpty()) {
            List<Integer> severityLevels = new ArrayList<>();
            for (OsvAffectedPackage vuln : advisory.getAffectedPackages()) {
                severityLevels.add(vuln.getSeverity().getLevel());
            }
            Collections.sort(severityLevels);
            return getSeverityByLevel(severityLevels.getLast());
        }
        return Severity.UNASSIGNED;
    }

    public Vulnerability.Source extractSource(String vulnId) {
        final String sourceId = vulnId.split("-")[0];
        return switch (sourceId) {
            case "GHSA" -> Vulnerability.Source.GITHUB;
            case "CVE" -> Vulnerability.Source.NVD;
            default -> Vulnerability.Source.OSV;
        };
    }

    public VulnerableSoftware mapAffectedPackageToVulnerableSoftware(final QueryManager qm, final OsvAffectedPackage affectedPackage) {
        if (affectedPackage.getPurl() == null) {
            LOGGER.debug("No PURL provided for affected package " + affectedPackage.getPackageName() + " - skipping");
            return null;
        }

        final PackageURL purl;
        try {
            purl = new PackageURL(affectedPackage.getPurl());
        } catch (MalformedPackageURLException e) {
            LOGGER.debug("Invalid PURL provided for affected package  " + affectedPackage.getPackageName() + " - skipping", e);
            return null;
        }

        // Other sources do not populate the versionStartIncluding with 0.
        // Semantically, versionStartIncluding=null is equivalent to >=0.
        // Omit zero values here for consistency's sake.
        final String versionStartIncluding = Optional.ofNullable(affectedPackage.getLowerVersionRange())
                .filter(version -> !"0".equals(version))
                .orElse(null);
        final String versionEndExcluding = affectedPackage.getUpperVersionRangeExcluding();
        final String versionEndIncluding = affectedPackage.getUpperVersionRangeIncluding();

        VulnerableSoftware vs = qm.getVulnerableSoftwareByPurl(purl.getType(), purl.getNamespace(), purl.getName(),
                purl.getVersion(), versionEndExcluding, versionEndIncluding, null, versionStartIncluding);
        if (vs != null) {
            return vs;
        }

        vs = new VulnerableSoftware();
        vs.setPurlType(purl.getType());
        vs.setPurlNamespace(purl.getNamespace());
        vs.setPurlName(purl.getName());
        vs.setPurl(purl.canonicalize());
        vs.setVulnerable(true);
        vs.setVersion(affectedPackage.getVersion());
        vs.setVersionStartIncluding(versionStartIncluding);
        vs.setVersionEndExcluding(versionEndExcluding);
        vs.setVersionEndIncluding(versionEndIncluding);
        return vs;
    }

    public List<String> getEcosystems() {
        ArrayList<String> ecosystems = new ArrayList<>();
        String url = this.osvBaseUrl + "ecosystems.txt";
        HttpUriRequest request = new HttpGet(url);
        try (final CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
            final StatusLine status = response.getStatusLine();
            if (status.getStatusCode() == HttpStatus.SC_OK) {
                try (InputStream in = response.getEntity().getContent();
                     Scanner scanner = new Scanner(in, StandardCharsets.UTF_8)) {
                    while (scanner.hasNextLine()) {
                        final String line = scanner.nextLine();
                        if(!line.isBlank()) {
                            ecosystems.add(line.trim());
                        }
                    }
                }
            } else {
                LOGGER.error("Ecosystem download failed : " + status.getStatusCode() + ": " + status.getReasonPhrase());
            }
        } catch (Exception ex) {
            LOGGER.error("Exception while executing Http request for ecosystems", ex);
        }
        return ecosystems;
    }

    public Set<String> getEnabledEcosystems() {
        return Optional.ofNullable(this.ecosystems)
                .orElseGet(Collections::emptySet);
    }

}
