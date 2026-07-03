# ZAP Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Phase 1 OWASP ZAP web scanning to JASCA so users can launch URL scans and review ZAP results inside JASCA while ZAP runs as a separate service.

**Architecture:** JASCA API calls a separate ZAP API service, stores the raw ZAP JSON, normalizes alerts through a ZAP parser, and reuses existing scan result persistence. The Web app adds ZAP as a scanner type with URL input and renders ZAP results using web-risk language instead of Trivy package language.

**Tech Stack:** NestJS, Prisma, PostgreSQL, Next.js/React, TanStack Query, Docker, OWASP ZAP API.

---

## File Structure

- Modify: `apps/api/prisma/schema.prisma`
  - Add `ZAP_JSON` to `SourceType`.
- Create: `apps/api/prisma/migrations/20260703090000_add_zap_source_type/migration.sql`
  - PostgreSQL enum migration for `SourceType`.
- Create: `apps/api/src/modules/scans/services/zap-parser.service.ts`
  - Convert ZAP alerts into `ParsedScanResult`.
- Create: `apps/api/src/modules/scans/services/zap-parser.service.spec.ts`
  - Unit tests for risk mapping and field preservation.
- Create: `apps/api/src/modules/scans/services/zap-policy.service.ts`
  - Validate target URLs against ZAP admin allowlist/denylist.
- Create: `apps/api/src/modules/scans/services/zap-policy.service.spec.ts`
  - Unit tests for allowed and blocked URLs.
- Create: `apps/api/src/modules/scans/services/zap-client.service.ts`
  - Thin ZAP API client for version, spider, passive alerts, stop.
- Create: `apps/api/src/modules/scans/services/zap-client.service.spec.ts`
  - Mocked HTTP tests for URL construction and errors.
- Create: `apps/api/src/modules/scans/services/zap-scan.service.ts`
  - Orchestrate baseline/passive scan workflow and attach execution evidence.
- Create: `apps/api/src/modules/scans/services/zap-scan.service.spec.ts`
  - Mock ZAP client and policy service to verify successful scan and blocked scan.
- Modify: `apps/api/src/modules/scans/scans.module.ts`
  - Register ZAP services.
- Modify: `apps/api/src/modules/scans/scans.controller.ts`
  - Add `POST /api/scans/scan/zap` and cancellation support.
- Modify: `apps/api/src/modules/scans/scans.service.ts`
  - Route `SourceType.ZAP_JSON` through `ZapParserService`.
- Modify: `apps/api/src/modules/scans/dto/upload-scan.dto.ts`
  - Allow `ZAP_JSON`.
- Modify: `apps/api/src/modules/settings/settings.service.ts`
  - Add safe default `zap` settings.
- Modify: `apps/web/src/lib/api-hooks.ts`
  - Add ZAP settings type and `scanZapTarget` mutation.
- Modify: `apps/web/src/app/admin/trivy-settings/page.tsx`
  - Add ZAP scanner settings panel or separate scanner section in the existing scanner settings screen.
- Modify: `apps/web/src/app/dashboard/scans/new/page.tsx`
  - Add ZAP scanner option with URL target input.
- Modify: `apps/web/src/app/dashboard/scans/page.tsx`
  - Display ZAP as a scanner and show web risk summary.
- Modify: `apps/web/src/app/dashboard/scans/[id]/page.tsx`
  - Render ZAP-specific detail sections.
- Modify: `docker/monolith/deploy-existing-layout.env.example`
  - Add `ZAP_BASE_URL` and `ZAP_API_KEY` examples.
- Modify: `docker/monolith/deploy-existing-layout.sh`
  - Pass ZAP environment variables to JASCA.
- Modify: `k8s/monolith/configmap.yaml`
  - Add ZAP internal service URL example.
- Modify: `k8s/monolith/secret.example.yaml`
  - Add ZAP API key example.
- Create: `k8s/zap-scanner/deployment.yaml`
  - Separate ZAP Deployment for future k8s migration.
- Create: `k8s/zap-scanner/service.yaml`
  - Internal Service for JASCA -> ZAP.
- Create: `k8s/zap-scanner/kustomization.yaml`
  - Bundle ZAP scanner manifests.

---

### Task 1: Add ZAP Source Type

**Files:**
- Modify: `apps/api/prisma/schema.prisma`
- Create: `apps/api/prisma/migrations/20260703090000_add_zap_source_type/migration.sql`
- Modify: `apps/api/src/modules/scans/dto/upload-scan.dto.ts`

- [ ] **Step 1: Write the enum migration**

Create `apps/api/prisma/migrations/20260703090000_add_zap_source_type/migration.sql`:

```sql
ALTER TYPE "SourceType" ADD VALUE IF NOT EXISTS 'ZAP_JSON';
```

- [ ] **Step 2: Add Prisma enum value**

In `apps/api/prisma/schema.prisma`, update `enum SourceType`:

```prisma
enum SourceType {
  TRIVY_JSON
  TRIVY_SARIF
  CHECKOV_JSON
  ZAP_JSON
  CI_BAMBOO
  CI_GITLAB
  CI_JENKINS
  CI_GITHUB_ACTIONS
  MANUAL
}
```

- [ ] **Step 3: Add DTO enum value**

In `apps/api/src/modules/scans/dto/upload-scan.dto.ts`, include `ZAP_JSON` in the `ApiProperty` enum list:

```ts
enum: [
    'TRIVY_JSON',
    'TRIVY_SARIF',
    'CHECKOV_JSON',
    'ZAP_JSON',
    'CI_BAMBOO',
    'CI_GITLAB',
    'CI_JENKINS',
    'CI_GITHUB_ACTIONS',
    'MANUAL',
],
```

- [ ] **Step 4: Generate Prisma client**

Run:

```powershell
pnpm --filter @jasca/api prisma:generate
```

Expected: command exits 0 and Prisma Client generation succeeds.

- [ ] **Step 5: Commit**

```powershell
git add apps/api/prisma/schema.prisma apps/api/prisma/migrations/20260703090000_add_zap_source_type/migration.sql apps/api/src/modules/scans/dto/upload-scan.dto.ts
git commit -m "Add ZAP scan source type"
```

---

### Task 2: Implement ZAP Result Parser

**Files:**
- Create: `apps/api/src/modules/scans/services/zap-parser.service.spec.ts`
- Create: `apps/api/src/modules/scans/services/zap-parser.service.ts`

- [ ] **Step 1: Write parser tests**

Create `apps/api/src/modules/scans/services/zap-parser.service.spec.ts`:

```ts
import { BadRequestException } from '@nestjs/common';
import { ZapParserService } from './zap-parser.service';

describe('ZapParserService', () => {
    const service = new ZapParserService();

    it('maps ZAP alerts to JASCA vulnerabilities', () => {
        const parsed = service.parse({
            site: [
                {
                    '@name': 'https://app.internal',
                    alerts: [
                        {
                            pluginid: '10038',
                            alert: 'Content Security Policy Header Not Set',
                            riskcode: '2',
                            riskdesc: 'Medium (High)',
                            confidence: 'High',
                            desc: '<p>CSP header is missing.</p>',
                            solution: '<p>Set Content-Security-Policy.</p>',
                            reference: '<p>https://example.com/csp</p>',
                            cweid: '693',
                            wascid: '15',
                            instances: [
                                {
                                    uri: 'https://app.internal/login',
                                    method: 'GET',
                                    param: '',
                                    evidence: 'Missing CSP',
                                    attack: '',
                                },
                            ],
                        },
                    ],
                },
            ],
            Metadata: {
                JascaScanEvidence: {
                    scanner: 'zap',
                    targetUrl: 'https://app.internal',
                    scanMode: 'baseline',
                },
            },
        });

        expect(parsed.artifactType).toBe('zap');
        expect(parsed.artifactName).toBe('https://app.internal');
        expect(parsed.vulnerabilities).toEqual([
            expect.objectContaining({
                cveId: 'ZAP-10038',
                severity: 'MEDIUM',
                title: 'Content Security Policy Header Not Set',
                pkgName: 'https://app.internal/login',
                pkgVersion: 'GET',
                fixedVersion: 'Set Content-Security-Policy.',
                pkgPath: 'https://app.internal/login',
                cweIds: ['CWE-693'],
            }),
        ]);
        expect(parsed.vulnerabilities[0].layer).toEqual(expect.objectContaining({
            scanner: 'zap',
            confidence: 'High',
            wascId: '15',
            evidence: 'Missing CSP',
        }));
    });

    it('maps informational alerts to UNKNOWN', () => {
        const parsed = service.parse({
            site: [{
                '@name': 'https://app.internal',
                alerts: [{
                    pluginid: '10027',
                    alert: 'Information Disclosure',
                    riskdesc: 'Informational (Medium)',
                    instances: [{ uri: 'https://app.internal', method: 'GET' }],
                }],
            }],
        });

        expect(parsed.vulnerabilities[0].severity).toBe('UNKNOWN');
    });

    it('rejects empty or invalid ZAP reports', () => {
        expect(() => service.parse(null)).toThrow(BadRequestException);
        expect(() => service.parse({ site: [] })).toThrow(BadRequestException);
    });
});
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```powershell
pnpm --filter @jasca/api test -- zap-parser.service.spec.ts
```

Expected: FAIL because `zap-parser.service.ts` does not exist.

- [ ] **Step 3: Implement parser**

Create `apps/api/src/modules/scans/services/zap-parser.service.ts`:

```ts
import { BadRequestException, Injectable } from '@nestjs/common';
import { Severity } from '@prisma/client';
import { ParsedScanResult, ParsedVulnerability } from './trivy-parser.service';

type ZapInstance = {
    uri?: string;
    method?: string;
    param?: string;
    evidence?: string;
    attack?: string;
};

type ZapAlert = {
    pluginid?: string;
    alert?: string;
    name?: string;
    riskdesc?: string;
    risk?: string;
    confidence?: string;
    desc?: string;
    description?: string;
    solution?: string;
    reference?: string;
    cweid?: string;
    wascid?: string;
    instances?: ZapInstance[];
};

type ZapSite = {
    '@name'?: string;
    name?: string;
    alerts?: ZapAlert[];
};

@Injectable()
export class ZapParserService {
    parse(rawResult: any): ParsedScanResult {
        if (!rawResult) {
            throw new BadRequestException('Empty ZAP scan result');
        }

        const evidence = rawResult?.Metadata?.JascaScanEvidence || {};
        const sites: ZapSite[] = Array.isArray(rawResult.site)
            ? rawResult.site
            : Array.isArray(rawResult.sites)
                ? rawResult.sites
                : [];

        const vulnerabilities = sites.flatMap((site) => this.parseSite(site));

        if (sites.length === 0 || vulnerabilities.length === 0) {
            throw new BadRequestException('Invalid ZAP JSON format');
        }

        return {
            trivyVersion: rawResult?.zapVersion ? `zap-${rawResult.zapVersion}` : 'zap',
            schemaVersion: 'zap-json',
            artifactName: evidence.targetUrl || sites[0]?.['@name'] || sites[0]?.name || 'zap-scan',
            artifactType: 'zap',
            vulnerabilities,
        };
    }

    private parseSite(site: ZapSite): ParsedVulnerability[] {
        const siteName = site['@name'] || site.name || 'web-target';
        const alerts = Array.isArray(site.alerts) ? site.alerts : [];

        return alerts.flatMap((alert) => {
            const instances = Array.isArray(alert.instances) && alert.instances.length > 0
                ? alert.instances
                : [{ uri: siteName, method: 'GET' }];

            return instances.map((instance) => this.toVulnerability(alert, instance, siteName));
        });
    }

    private toVulnerability(alert: ZapAlert, instance: ZapInstance, siteName: string): ParsedVulnerability {
        const url = instance.uri || siteName;
        const method = instance.method || 'GET';
        const pluginId = alert.pluginid || 'unknown';
        const solution = this.stripHtml(alert.solution);

        return {
            cveId: `ZAP-${pluginId}`,
            title: alert.alert || alert.name || `ZAP Alert ${pluginId}`,
            description: this.stripHtml(alert.desc || alert.description),
            severity: this.mapRisk(alert.riskdesc || alert.risk),
            references: this.extractReferences(alert.reference),
            cweIds: alert.cweid && alert.cweid !== '-1' ? [`CWE-${alert.cweid}`] : [],
            pkgName: url,
            pkgVersion: method,
            fixedVersion: solution,
            pkgPath: url,
            layer: {
                scanner: 'zap',
                confidence: alert.confidence,
                parameter: instance.param,
                evidence: instance.evidence,
                attack: instance.attack,
                wascId: alert.wascid,
                site: siteName,
            },
        };
    }

    private mapRisk(value?: string): Severity {
        const normalized = String(value || '').toUpperCase();
        if (normalized.includes('HIGH')) return 'HIGH';
        if (normalized.includes('MEDIUM')) return 'MEDIUM';
        if (normalized.includes('LOW')) return 'LOW';
        return 'UNKNOWN';
    }

    private stripHtml(value?: string): string | undefined {
        if (!value) return undefined;
        return value
            .replace(/<[^>]+>/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();
    }

    private extractReferences(value?: string): string[] {
        const clean = this.stripHtml(value);
        if (!clean) return [];
        return clean
            .split(/\s+/)
            .filter((item) => /^https?:\/\//i.test(item));
    }
}
```

- [ ] **Step 4: Run parser tests**

Run:

```powershell
pnpm --filter @jasca/api test -- zap-parser.service.spec.ts
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add apps/api/src/modules/scans/services/zap-parser.service.ts apps/api/src/modules/scans/services/zap-parser.service.spec.ts
git commit -m "Add ZAP result parser"
```

---

### Task 3: Add Safe ZAP Settings Defaults

**Files:**
- Modify: `apps/api/src/modules/settings/settings.service.ts`
- Modify: `apps/web/src/lib/api-hooks.ts`

- [ ] **Step 1: Add API settings default**

In `apps/api/src/modules/settings/settings.service.ts`, add this object to `defaultSettings`:

```ts
zap: {
    enabled: false,
    zapBaseUrl: 'http://zap-scanner:8080',
    apiKey: '',
    connectTimeoutSeconds: 10,
    maxScanDurationMinutes: 30,
    maxConcurrentScans: 1,
    allowBaselineScan: true,
    allowActiveScan: false,
    allowedTargetPatterns: [],
    blockedTargetPatterns: [],
    defaultRiskThresholdForNotification: 'HIGH',
},
```

- [ ] **Step 2: Add frontend type and hook**

In `apps/web/src/lib/api-hooks.ts`, add:

```ts
export interface ZapSettings {
    enabled: boolean;
    zapBaseUrl: string;
    apiKey?: string;
    connectTimeoutSeconds: number;
    maxScanDurationMinutes: number;
    maxConcurrentScans: number;
    allowBaselineScan: boolean;
    allowActiveScan: boolean;
    allowedTargetPatterns: string[];
    blockedTargetPatterns: string[];
    defaultRiskThresholdForNotification: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
}

export function useZapSettings() {
    return useSettings<ZapSettings>('zap');
}
```

- [ ] **Step 3: Run API build**

Run:

```powershell
pnpm --filter @jasca/api build
```

Expected: PASS.

- [ ] **Step 4: Run Web build**

Run:

```powershell
pnpm --filter @jasca/web build
```

Expected: PASS. Windows may print Next.js standalone symlink `EPERM` warnings but command must exit 0.

- [ ] **Step 5: Commit**

```powershell
git add apps/api/src/modules/settings/settings.service.ts apps/web/src/lib/api-hooks.ts
git commit -m "Add ZAP scanner settings defaults"
```

---

### Task 4: Implement Target Policy Validation

**Files:**
- Create: `apps/api/src/modules/scans/services/zap-policy.service.spec.ts`
- Create: `apps/api/src/modules/scans/services/zap-policy.service.ts`

- [ ] **Step 1: Write policy tests**

Create `apps/api/src/modules/scans/services/zap-policy.service.spec.ts`:

```ts
import { BadRequestException } from '@nestjs/common';
import { ZapPolicyService, ZapSettings } from './zap-policy.service';

describe('ZapPolicyService', () => {
    const service = new ZapPolicyService();
    const settings: ZapSettings = {
        enabled: true,
        zapBaseUrl: 'http://zap-scanner:8080',
        apiKey: 'secret',
        connectTimeoutSeconds: 10,
        maxScanDurationMinutes: 30,
        maxConcurrentScans: 1,
        allowBaselineScan: true,
        allowActiveScan: false,
        allowedTargetPatterns: ['*.internal', 'https://app.koreacb.com'],
        blockedTargetPatterns: ['admin.internal'],
        defaultRiskThresholdForNotification: 'HIGH',
    };

    it('allows a matching internal target', () => {
        expect(service.validateTargetUrl('https://demo.internal/login', settings).href)
            .toBe('https://demo.internal/login');
    });

    it('blocks targets when ZAP is disabled', () => {
        expect(() => service.validateTargetUrl('https://demo.internal', { ...settings, enabled: false }))
            .toThrow(BadRequestException);
    });

    it('blocks targets outside the allowlist', () => {
        expect(() => service.validateTargetUrl('https://example.com', settings))
            .toThrow(BadRequestException);
    });

    it('blocks explicit denylist matches', () => {
        expect(() => service.validateTargetUrl('https://admin.internal', settings))
            .toThrow(BadRequestException);
    });

    it('rejects non-http URLs', () => {
        expect(() => service.validateTargetUrl('file:///etc/passwd', settings))
            .toThrow(BadRequestException);
    });
});
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```powershell
pnpm --filter @jasca/api test -- zap-policy.service.spec.ts
```

Expected: FAIL because `zap-policy.service.ts` does not exist.

- [ ] **Step 3: Implement policy service**

Create `apps/api/src/modules/scans/services/zap-policy.service.ts`:

```ts
import { BadRequestException, Injectable } from '@nestjs/common';

export interface ZapSettings {
    enabled: boolean;
    zapBaseUrl: string;
    apiKey?: string;
    connectTimeoutSeconds: number;
    maxScanDurationMinutes: number;
    maxConcurrentScans: number;
    allowBaselineScan: boolean;
    allowActiveScan: boolean;
    allowedTargetPatterns: string[];
    blockedTargetPatterns: string[];
    defaultRiskThresholdForNotification: string;
}

@Injectable()
export class ZapPolicyService {
    validateTargetUrl(targetUrl: string, settings: ZapSettings): URL {
        if (!settings.enabled) {
            throw new BadRequestException('ZAP scanning is disabled by administrator settings.');
        }

        let parsed: URL;
        try {
            parsed = new URL(targetUrl);
        } catch {
            throw new BadRequestException('Invalid ZAP target URL.');
        }

        if (!['http:', 'https:'].includes(parsed.protocol)) {
            throw new BadRequestException('ZAP target URL must use http or https.');
        }

        const allowed = settings.allowedTargetPatterns || [];
        if (allowed.length === 0) {
            throw new BadRequestException('ZAP target allowlist is empty. Ask an administrator to configure allowed targets.');
        }

        if (!allowed.some((pattern) => this.matchesPattern(parsed, pattern))) {
            throw new BadRequestException('ZAP target URL is not allowed by administrator policy.');
        }

        const blocked = settings.blockedTargetPatterns || [];
        if (blocked.some((pattern) => this.matchesPattern(parsed, pattern))) {
            throw new BadRequestException('ZAP target URL is blocked by administrator policy.');
        }

        return parsed;
    }

    private matchesPattern(url: URL, pattern: string): boolean {
        const normalized = pattern.trim().toLowerCase();
        if (!normalized) return false;

        const full = url.href.toLowerCase().replace(/\/+$/, '');
        const host = url.hostname.toLowerCase();

        if (normalized.startsWith('http://') || normalized.startsWith('https://')) {
            return full === normalized.replace(/\/+$/, '') || full.startsWith(`${normalized.replace(/\/+$/, '')}/`);
        }

        if (normalized.startsWith('*.')) {
            const suffix = normalized.slice(1);
            return host.endsWith(suffix);
        }

        return host === normalized || host.endsWith(`.${normalized}`);
    }
}
```

- [ ] **Step 4: Run policy tests**

Run:

```powershell
pnpm --filter @jasca/api test -- zap-policy.service.spec.ts
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add apps/api/src/modules/scans/services/zap-policy.service.ts apps/api/src/modules/scans/services/zap-policy.service.spec.ts
git commit -m "Add ZAP target policy validation"
```

---

### Task 5: Implement ZAP API Client

**Files:**
- Create: `apps/api/src/modules/scans/services/zap-client.service.spec.ts`
- Create: `apps/api/src/modules/scans/services/zap-client.service.ts`

- [ ] **Step 1: Write client tests**

Create `apps/api/src/modules/scans/services/zap-client.service.spec.ts`:

```ts
import { ServiceUnavailableException } from '@nestjs/common';
import { ZapClientService } from './zap-client.service';

describe('ZapClientService', () => {
    let originalFetch: typeof global.fetch;

    beforeEach(() => {
        originalFetch = global.fetch;
    });

    afterEach(() => {
        global.fetch = originalFetch;
    });

    it('calls ZAP version endpoint with API key', async () => {
        global.fetch = jest.fn().mockResolvedValue({
            ok: true,
            json: async () => ({ version: '2.15.0' }),
        } as any);

        const client = new ZapClientService();
        await expect(client.getVersion({ baseUrl: 'http://zap:8080', apiKey: 'key', timeoutMs: 1000 }))
            .resolves.toBe('2.15.0');

        expect(global.fetch).toHaveBeenCalledWith(
            'http://zap:8080/JSON/core/view/version/?apikey=key',
            expect.objectContaining({ method: 'GET' }),
        );
    });

    it('throws a clear error when ZAP is unreachable', async () => {
        global.fetch = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'));

        const client = new ZapClientService();
        await expect(client.getVersion({ baseUrl: 'http://zap:8080', apiKey: '', timeoutMs: 1000 }))
            .rejects.toThrow(ServiceUnavailableException);
    });
});
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```powershell
pnpm --filter @jasca/api test -- zap-client.service.spec.ts
```

Expected: FAIL because `zap-client.service.ts` does not exist.

- [ ] **Step 3: Implement client service**

Create `apps/api/src/modules/scans/services/zap-client.service.ts`:

```ts
import { Injectable, ServiceUnavailableException } from '@nestjs/common';

export interface ZapClientOptions {
    baseUrl: string;
    apiKey?: string;
    timeoutMs: number;
}

@Injectable()
export class ZapClientService {
    async getVersion(options: ZapClientOptions): Promise<string> {
        const result = await this.getJson<{ version?: string }>(options, '/JSON/core/view/version/', {});
        return result.version || 'unknown';
    }

    async spiderScan(options: ZapClientOptions, targetUrl: string): Promise<string> {
        const result = await this.getJson<{ scan?: string }>(options, '/JSON/spider/action/scan/', { url: targetUrl });
        return result.scan || '';
    }

    async spiderStatus(options: ZapClientOptions, scanId: string): Promise<number> {
        const result = await this.getJson<{ status?: string }>(options, '/JSON/spider/view/status/', { scanId });
        return Number(result.status || 0);
    }

    async alerts(options: ZapClientOptions, targetUrl: string): Promise<any[]> {
        const result = await this.getJson<{ alerts?: any[] }>(options, '/JSON/core/view/alerts/', {
            baseurl: targetUrl,
            start: '0',
            count: '999999',
        });
        return result.alerts || [];
    }

    async stopSpider(options: ZapClientOptions, scanId: string): Promise<void> {
        await this.getJson(options, '/JSON/spider/action/stop/', { scanId });
    }

    private async getJson<T>(options: ZapClientOptions, path: string, query: Record<string, string>): Promise<T> {
        const url = new URL(path, options.baseUrl.replace(/\/+$/, '/') );
        if (options.apiKey) url.searchParams.set('apikey', options.apiKey);
        for (const [key, value] of Object.entries(query)) {
            url.searchParams.set(key, value);
        }

        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), options.timeoutMs);
        try {
            const response = await fetch(url.toString(), { method: 'GET', signal: controller.signal });
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            return await response.json() as T;
        } catch (error) {
            throw new ServiceUnavailableException(`ZAP service call failed: ${(error as Error).message}`);
        } finally {
            clearTimeout(timer);
        }
    }
}
```

- [ ] **Step 4: Run client tests**

Run:

```powershell
pnpm --filter @jasca/api test -- zap-client.service.spec.ts
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add apps/api/src/modules/scans/services/zap-client.service.ts apps/api/src/modules/scans/services/zap-client.service.spec.ts
git commit -m "Add ZAP API client"
```

---

### Task 6: Implement ZAP Scan Orchestrator

**Files:**
- Create: `apps/api/src/modules/scans/services/zap-scan.service.spec.ts`
- Create: `apps/api/src/modules/scans/services/zap-scan.service.ts`

- [ ] **Step 1: Write scan service tests**

Create `apps/api/src/modules/scans/services/zap-scan.service.spec.ts`:

```ts
import { BadRequestException } from '@nestjs/common';
import { ZapScanService } from './zap-scan.service';

describe('ZapScanService', () => {
    const settingsService = {
        get: jest.fn(),
    };
    const policyService = {
        validateTargetUrl: jest.fn(),
    };
    const zapClient = {
        getVersion: jest.fn(),
        spiderScan: jest.fn(),
        spiderStatus: jest.fn(),
        alerts: jest.fn(),
        stopSpider: jest.fn(),
    };

    beforeEach(() => {
        jest.resetAllMocks();
        settingsService.get.mockResolvedValue({
            enabled: true,
            zapBaseUrl: 'http://zap:8080',
            apiKey: 'key',
            connectTimeoutSeconds: 10,
            maxScanDurationMinutes: 1,
            maxConcurrentScans: 1,
            allowBaselineScan: true,
            allowActiveScan: false,
            allowedTargetPatterns: ['*.internal'],
            blockedTargetPatterns: [],
            defaultRiskThresholdForNotification: 'HIGH',
        });
        policyService.validateTargetUrl.mockReturnValue(new URL('https://demo.internal'));
        zapClient.getVersion.mockResolvedValue('2.15.0');
        zapClient.spiderScan.mockResolvedValue('1');
        zapClient.spiderStatus.mockResolvedValue(100);
        zapClient.alerts.mockResolvedValue([
            {
                pluginid: '10038',
                alert: 'Content Security Policy Header Not Set',
                riskdesc: 'Medium (High)',
                confidence: 'High',
                instances: [{ uri: 'https://demo.internal', method: 'GET', evidence: 'Missing CSP' }],
            },
        ]);
    });

    it('runs a baseline ZAP scan and returns ZAP-shaped JSON', async () => {
        const service = new ZapScanService(settingsService as any, policyService as any, zapClient as any);
        const result = await service.scanUrl({ targetUrl: 'https://demo.internal', scanMode: 'baseline' }, 'op-1');

        expect(result.site[0].alerts).toHaveLength(1);
        expect(result.Metadata.JascaScanEvidence).toEqual(expect.objectContaining({
            scanner: 'zap',
            targetUrl: 'https://demo.internal',
            scanMode: 'baseline',
            zapVersion: '2.15.0',
        }));
    });

    it('rejects active scan when disabled', async () => {
        const service = new ZapScanService(settingsService as any, policyService as any, zapClient as any);
        await expect(service.scanUrl({ targetUrl: 'https://demo.internal', scanMode: 'active' }, 'op-1'))
            .rejects.toThrow(BadRequestException);
    });
});
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```powershell
pnpm --filter @jasca/api test -- zap-scan.service.spec.ts
```

Expected: FAIL because `zap-scan.service.ts` does not exist.

- [ ] **Step 3: Implement scan service**

Create `apps/api/src/modules/scans/services/zap-scan.service.ts`:

```ts
import { BadRequestException, Injectable, Logger, RequestTimeoutException } from '@nestjs/common';
import { SettingsService } from '../../settings/settings.service';
import { ZapClientService, ZapClientOptions } from './zap-client.service';
import { ZapPolicyService, ZapSettings } from './zap-policy.service';

export interface ZapScanOptions {
    targetUrl: string;
    scanMode?: 'baseline' | 'passive' | 'active';
}

@Injectable()
export class ZapScanService {
    private readonly logger = new Logger(ZapScanService.name);
    private readonly activeScans = new Map<string, { scanId?: string; cancelled: boolean }>();

    constructor(
        private readonly settingsService: SettingsService,
        private readonly policyService: ZapPolicyService,
        private readonly zapClient: ZapClientService,
    ) {}

    async scanUrl(options: ZapScanOptions, operationId?: string): Promise<any> {
        const startedAt = Date.now();
        const settings = await this.getSettings();
        const target = this.policyService.validateTargetUrl(options.targetUrl, settings);
        const scanMode = options.scanMode || 'baseline';

        if (scanMode === 'active' && !settings.allowActiveScan) {
            throw new BadRequestException('ZAP Active Scan is disabled by administrator settings.');
        }

        if (!settings.allowBaselineScan && scanMode !== 'active') {
            throw new BadRequestException('ZAP Baseline Scan is disabled by administrator settings.');
        }

        const clientOptions: ZapClientOptions = {
            baseUrl: settings.zapBaseUrl,
            apiKey: settings.apiKey,
            timeoutMs: settings.connectTimeoutSeconds * 1000,
        };
        const timeoutMs = settings.maxScanDurationMinutes * 60 * 1000;

        if (operationId) this.activeScans.set(operationId, { cancelled: false });

        try {
            const zapVersion = await this.zapClient.getVersion(clientOptions);
            const spiderScanId = await this.zapClient.spiderScan(clientOptions, target.href);
            if (operationId) this.activeScans.set(operationId, { scanId: spiderScanId, cancelled: false });

            await this.waitForSpider(clientOptions, spiderScanId, timeoutMs, operationId);
            const alerts = await this.zapClient.alerts(clientOptions, target.href);

            return {
                zapVersion,
                site: [
                    {
                        '@name': target.origin,
                        alerts,
                    },
                ],
                Metadata: {
                    JascaScanEvidence: {
                        executedBy: 'jasca',
                        scanner: 'zap',
                        completed: true,
                        targetUrl: target.href,
                        scanMode,
                        zapVersion,
                        startedAt: new Date(startedAt).toISOString(),
                        completedAt: new Date().toISOString(),
                        durationMs: Date.now() - startedAt,
                        options: {
                            maxScanDurationMinutes: settings.maxScanDurationMinutes,
                            allowActiveScan: settings.allowActiveScan,
                        },
                    },
                },
            };
        } finally {
            if (operationId) this.activeScans.delete(operationId);
        }
    }

    async cancelScan(operationId: string): Promise<boolean> {
        const active = this.activeScans.get(operationId);
        if (!active) return false;
        active.cancelled = true;
        this.activeScans.set(operationId, active);
        const settings = await this.getSettings();
        if (active.scanId) {
            await this.zapClient.stopSpider({
                baseUrl: settings.zapBaseUrl,
                apiKey: settings.apiKey,
                timeoutMs: settings.connectTimeoutSeconds * 1000,
            }, active.scanId).catch((error) => this.logger.warn(`Failed to stop ZAP spider: ${(error as Error).message}`));
        }
        return true;
    }

    private async waitForSpider(options: ZapClientOptions, scanId: string, timeoutMs: number, operationId?: string): Promise<void> {
        const deadline = Date.now() + timeoutMs;
        while (Date.now() < deadline) {
            if (operationId && this.activeScans.get(operationId)?.cancelled) {
                throw new BadRequestException('ZAP scan was cancelled by the user');
            }
            const status = await this.zapClient.spiderStatus(options, scanId);
            if (status >= 100) return;
            await new Promise((resolve) => setTimeout(resolve, 2000));
        }
        throw new RequestTimeoutException(`ZAP scan timed out after ${timeoutMs}ms`);
    }

    private async getSettings(): Promise<ZapSettings> {
        const defaults: ZapSettings = {
            enabled: false,
            zapBaseUrl: 'http://zap-scanner:8080',
            apiKey: '',
            connectTimeoutSeconds: 10,
            maxScanDurationMinutes: 30,
            maxConcurrentScans: 1,
            allowBaselineScan: true,
            allowActiveScan: false,
            allowedTargetPatterns: [],
            blockedTargetPatterns: [],
            defaultRiskThresholdForNotification: 'HIGH',
        };
        const stored = await this.settingsService.get('zap') as Partial<ZapSettings> | null;
        return { ...defaults, ...(stored || {}) };
    }
}
```

- [ ] **Step 4: Run scan service tests**

Run:

```powershell
pnpm --filter @jasca/api test -- zap-scan.service.spec.ts
```

Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add apps/api/src/modules/scans/services/zap-scan.service.ts apps/api/src/modules/scans/services/zap-scan.service.spec.ts
git commit -m "Add ZAP scan orchestration"
```

---

### Task 7: Wire ZAP Into Scan API

**Files:**
- Modify: `apps/api/src/modules/scans/scans.module.ts`
- Modify: `apps/api/src/modules/scans/scans.service.ts`
- Modify: `apps/api/src/modules/scans/scans.controller.ts`

- [ ] **Step 1: Register services in module**

In `apps/api/src/modules/scans/scans.module.ts`, import and add providers:

```ts
import { ZapParserService } from './services/zap-parser.service';
import { ZapPolicyService } from './services/zap-policy.service';
import { ZapClientService } from './services/zap-client.service';
import { ZapScanService } from './services/zap-scan.service';
```

Update providers:

```ts
providers: [
    ScansService,
    TrivyParserService,
    CheckovParserService,
    ZapParserService,
    VulnSyncService,
    TrivyScanService,
    CheckovScanService,
    ZapPolicyService,
    ZapClientService,
    ZapScanService,
],
```

- [ ] **Step 2: Route ZAP parser in ScansService**

In `apps/api/src/modules/scans/scans.service.ts`, import `ZapParserService`, add it to constructor, and change parser selection:

```ts
const parsed = dto.sourceType === 'CHECKOV_JSON'
    ? this.checkovParser.parse(rawResult)
    : dto.sourceType === 'ZAP_JSON'
        ? this.zapParser.parse(rawResult)
        : this.trivyParser.parse(rawResult, dto.sourceType);
```

- [ ] **Step 3: Add ZAP endpoint to controller**

In `apps/api/src/modules/scans/scans.controller.ts`, inject `ZapScanService` and add:

```ts
@Post('scan/zap')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('DEVELOPER', 'PROJECT_ADMIN', 'ORG_ADMIN', 'SECURITY_ADMIN')
@ApiBearerAuth()
@ApiOperation({ summary: 'Run a ZAP web scan against a URL target' })
async scanZapTarget(
    @Query('projectId') projectId: string | undefined,
    @Body() body: {
        targetUrl?: string;
        scanMode?: 'baseline' | 'passive' | 'active';
        projectName?: string;
        organizationId?: string;
        scanOperationId?: string;
    },
    @Req() req: Request,
) {
    if (!body.targetUrl) {
        throw new BadRequestException('targetUrl is required');
    }

    const rawResult = await this.zapScanService.scanUrl({
        targetUrl: body.targetUrl,
        scanMode: body.scanMode || 'baseline',
    }, body.scanOperationId);

    const user = (req as any).user;
    const savedScan = await this.scansService.uploadScan(projectId, {
        sourceType: SourceType.ZAP_JSON,
        projectName: body.projectName,
        organizationId: body.organizationId || user?.organizationId,
        imageRef: body.targetUrl,
    }, rawResult, {
        uploaderIp: req.ip || req.socket?.remoteAddress || 'unknown',
        userAgent: req.headers['user-agent'] || 'Browser ZAP Scan',
        uploadedById: user?.id,
    }, user);

    return savedScan;
}
```

- [ ] **Step 4: Extend cancel endpoint**

In `cancelTrivyScan`, call:

```ts
const zapCancelled = await this.zapScanService.cancelScan(operationId);
const cancelled = trivyCancelled || checkovCancelled || zapCancelled;
```

- [ ] **Step 5: Run API build**

Run:

```powershell
pnpm --filter @jasca/api build
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add apps/api/src/modules/scans/scans.module.ts apps/api/src/modules/scans/scans.service.ts apps/api/src/modules/scans/scans.controller.ts
git commit -m "Wire ZAP scans into API"
```

---

### Task 8: Add ZAP Admin Settings UI

**Files:**
- Modify: `apps/web/src/app/admin/trivy-settings/page.tsx`
- Modify: `apps/web/src/lib/api-hooks.ts`

- [ ] **Step 1: Add settings hook imports**

In `apps/web/src/app/admin/trivy-settings/page.tsx`, include `useZapSettings` and `type ZapSettings`:

```ts
import { useCheckovSettings, useTrivySettings, useUpdateSettings, useZapSettings, type CheckovSettings, type TrivySettings, type ZapSettings } from '@/lib/api-hooks';
```

- [ ] **Step 2: Add default ZAP UI state**

Add near other defaults:

```ts
const defaultZapConfig: ZapSettings = {
    enabled: false,
    zapBaseUrl: 'http://zap-scanner:8080',
    apiKey: '',
    connectTimeoutSeconds: 10,
    maxScanDurationMinutes: 30,
    maxConcurrentScans: 1,
    allowBaselineScan: true,
    allowActiveScan: false,
    allowedTargetPatterns: [],
    blockedTargetPatterns: [],
    defaultRiskThresholdForNotification: 'HIGH',
};
```

- [ ] **Step 3: Add state and save behavior**

Add:

```ts
const { data: zapSettings, isLoading: isZapLoading, refetch: refetchZap } = useZapSettings();
const [zapConfig, setZapConfig] = useState<ZapSettings>(defaultZapConfig);

useEffect(() => {
    if (zapSettings) setZapConfig({ ...defaultZapConfig, ...zapSettings });
}, [zapSettings]);

const updateZapConfig = <K extends keyof ZapSettings>(key: K, value: ZapSettings[K]) => {
    setZapConfig((prev) => ({ ...prev, [key]: value }));
};
```

Add a save button or include in existing save flow:

```ts
await updateSettings.mutateAsync({ key: 'zap', value: zapConfig });
refetchZap();
```

- [ ] **Step 4: Render ZAP settings panel**

Add a section with fields:

```tsx
<section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900">
    <h2 className="text-lg font-semibold text-slate-900 dark:text-white">ZAP 웹 스캔 설정</h2>
    <p className="mt-1 text-sm text-slate-500">ZAP은 별도 스캐너 서비스로 실행되며, JASCA는 이 API를 호출해 결과를 저장합니다.</p>

    <label className="mt-4 flex items-center justify-between rounded-lg border p-3">
        <span>
            <span className="block font-medium">ZAP 스캔 활성화</span>
            <span className="text-sm text-slate-500">활성화해야 사용자 스캔 화면에 ZAP이 표시됩니다.</span>
        </span>
        <input type="checkbox" checked={zapConfig.enabled} onChange={(e) => updateZapConfig('enabled', e.target.checked)} />
    </label>

    <input aria-label="ZAP service URL" value={zapConfig.zapBaseUrl} onChange={(e) => updateZapConfig('zapBaseUrl', e.target.value)} />
    <input aria-label="ZAP API Key" value={zapConfig.apiKey || ''} onChange={(e) => updateZapConfig('apiKey', e.target.value)} type="password" />
    <textarea aria-label="Allowed ZAP targets" value={zapConfig.allowedTargetPatterns.join('\n')} onChange={(e) => updateZapConfig('allowedTargetPatterns', e.target.value.split(/\r?\n/).map((v) => v.trim()).filter(Boolean))} />
    <textarea aria-label="Blocked ZAP targets" value={zapConfig.blockedTargetPatterns.join('\n')} onChange={(e) => updateZapConfig('blockedTargetPatterns', e.target.value.split(/\r?\n/).map((v) => v.trim()).filter(Boolean))} />
</section>
```

When applying this snippet, match the existing page styling and do not leave raw unstyled inputs.

- [ ] **Step 5: Run Web build**

Run:

```powershell
pnpm --filter @jasca/web build
```

Expected: PASS with exit code 0.

- [ ] **Step 6: Commit**

```powershell
git add apps/web/src/app/admin/trivy-settings/page.tsx apps/web/src/lib/api-hooks.ts
git commit -m "Add ZAP admin settings UI"
```

---

### Task 9: Add ZAP Scan Creation UI and API Hook

**Files:**
- Modify: `apps/web/src/lib/api-hooks.ts`
- Modify: `apps/web/src/app/dashboard/scans/new/page.tsx`

- [ ] **Step 1: Add ZAP scan API hook**

In `apps/web/src/lib/api-hooks.ts`, add:

```ts
export interface ZapScanRequest {
    projectId?: string;
    targetUrl: string;
    scanMode: 'baseline' | 'passive' | 'active';
    projectName?: string;
    organizationId?: string;
    scanOperationId?: string;
}

export function useZapScan() {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: async (request: ZapScanRequest) => {
            const params = request.projectId ? `?projectId=${encodeURIComponent(request.projectId)}` : '';
            const response = await apiClient.post(`/scans/scan/zap${params}`, {
                targetUrl: request.targetUrl,
                scanMode: request.scanMode,
                projectName: request.projectName,
                organizationId: request.organizationId,
                scanOperationId: request.scanOperationId,
            });
            return response.data;
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['scans'] });
        },
    });
}
```

- [ ] **Step 2: Extend scanner type**

In `apps/web/src/app/dashboard/scans/new/page.tsx`, update:

```ts
type ScannerProvider = 'trivy' | 'checkov' | 'zap';
```

Add state:

```ts
const [zapTargetUrl, setZapTargetUrl] = useState('');
const [zapScanMode, setZapScanMode] = useState<'baseline' | 'passive' | 'active'>('baseline');
const zapScanMutation = useZapScan();
const isZapScan = isScanningTarget && scannerProvider === 'zap';
```

- [ ] **Step 3: Add ZAP scanner card**

Add to scanner selection array:

```ts
{ value: 'zap' as const, label: 'ZAP', description: '웹 URL 대상 DAST Baseline/Passive 스캔' },
```

- [ ] **Step 4: Render URL input when ZAP is selected**

In the main form area, when `isZapScan`:

```tsx
{isZapScan && (
    <div className="mb-6 rounded-xl border border-orange-500/30 bg-orange-500/10 p-4">
        <label className="mb-2 block text-sm font-medium text-orange-100">ZAP 대상 URL</label>
        <input
            type="url"
            value={zapTargetUrl}
            onChange={(e) => setZapTargetUrl(e.target.value)}
            aria-label="ZAP target URL"
            className="w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-orange-500"
        />
        <p className="mt-2 text-xs text-orange-100/80">관리자가 허용한 도메인/대역만 스캔할 수 있습니다.</p>
    </div>
)}
```

Hide the file dropzone for `isZapScan`.

- [ ] **Step 5: Submit ZAP scan separately**

At the top of `handleUpload`, add:

```ts
if (isZapScan) {
    if (!zapTargetUrl.trim()) {
        setErrorMessage('ZAP으로 검사할 URL을 입력해주세요.');
        return;
    }
    if (!selectedProjectId && !projectName.trim()) {
        setErrorMessage('프로젝트를 선택하거나 새 프로젝트 이름을 입력해주세요.');
        return;
    }
    setUploadStatus('uploading');
    const nextOperationId = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    setScanOperationId(nextOperationId);
    try {
        const scanResult = await zapScanMutation.mutateAsync({
            projectId: selectedProjectId || undefined,
            targetUrl: zapTargetUrl.trim(),
            scanMode: zapScanMode,
            projectName: !selectedProjectId ? projectName.trim() : undefined,
            organizationId: selectedOrgId || undefined,
            scanOperationId: nextOperationId,
        });
        setUploadStatus('success');
        setScanOperationId('');
        router.push(scanResult?.id ? `/dashboard/scans/${scanResult.id}` : '/dashboard/scans');
    } catch (error: any) {
        setUploadStatus('error');
        setScanOperationId('');
        setErrorMessage(error.message || 'ZAP 스캔에 실패했습니다.');
    }
    return;
}
```

- [ ] **Step 6: Update button labels**

When `isZapScan`, display:

```tsx
{uploadStatus === 'uploading' ? 'ZAP 스캔 중...' : 'ZAP 스캔 실행'}
```

- [ ] **Step 7: Run Web build**

Run:

```powershell
pnpm --filter @jasca/web build
```

Expected: PASS with exit code 0.

- [ ] **Step 8: Commit**

```powershell
git add apps/web/src/lib/api-hooks.ts apps/web/src/app/dashboard/scans/new/page.tsx
git commit -m "Add ZAP scan creation UI"
```

---

### Task 10: Render ZAP Results in List and Detail Pages

**Files:**
- Modify: `apps/web/src/app/dashboard/scans/page.tsx`
- Modify: `apps/web/src/app/dashboard/scans/[id]/page.tsx`

- [ ] **Step 1: Detect ZAP source type in list**

In `apps/web/src/app/dashboard/scans/page.tsx`, add `ZAP_JSON` checks beside existing Checkov logic:

```ts
const isZap = sourceType === 'ZAP_JSON';
```

Update summary label:

```tsx
{isZap && unknownTotal > 0 ? `Info ${unknownTotal}` : isCheckov ? `정책 위반 ${unknownTotal}` : `UNKNOWN ${unknownTotal}`}
```

Add scanner filter display option:

```tsx
<option value="ZAP_JSON">ZAP</option>
```

- [ ] **Step 2: Detect ZAP source type in detail**

In `apps/web/src/app/dashboard/scans/[id]/page.tsx`, add:

```ts
const isZapScan = sourceType === 'ZAP_JSON' || evidence?.scanner === 'zap' || (scan as any).artifactType === 'zap';
const scannerLabel = isZapScan ? 'ZAP' : isCheckovScan ? 'Checkov' : 'Trivy';
```

- [ ] **Step 3: Add ZAP summary cards**

For `isZapScan`, show:

```tsx
<div className="grid grid-cols-2 gap-3 md:grid-cols-4">
    <StatCard label="High" value={summary.high || 0} />
    <StatCard label="Medium" value={summary.medium || 0} />
    <StatCard label="Low" value={summary.low || 0} />
    <StatCard label="Informational" value={summary.unknown || 0} />
</div>
```

Use the existing stat card style from the page; do not introduce a new component unless the file already has one.

- [ ] **Step 4: Add ZAP-specific finding table labels**

For `isZapScan`, label fields as:

```tsx
Alert
Risk
URL
Method
Parameter
Evidence
Solution
References
```

Use existing vulnerability row data:

```ts
const zapMeta = item.layer || item.vulnerability?.layer || {};
```

Display:

```tsx
item.vulnerability?.title
item.pkgName
item.installedVersion
zapMeta.parameter
zapMeta.evidence
item.fixedVersion
```

- [ ] **Step 5: Run Web build**

Run:

```powershell
pnpm --filter @jasca/web build
```

Expected: PASS with exit code 0.

- [ ] **Step 6: Commit**

```powershell
git add apps/web/src/app/dashboard/scans/page.tsx apps/web/src/app/dashboard/scans/[id]/page.tsx
git commit -m "Render ZAP scan results"
```

---

### Task 11: Add Docker and Kubernetes ZAP Deployment Assets

**Files:**
- Modify: `docker/monolith/deploy-existing-layout.env.example`
- Modify: `docker/monolith/deploy-existing-layout.sh`
- Modify: `k8s/monolith/configmap.yaml`
- Modify: `k8s/monolith/secret.example.yaml`
- Create: `k8s/zap-scanner/deployment.yaml`
- Create: `k8s/zap-scanner/service.yaml`
- Create: `k8s/zap-scanner/kustomization.yaml`
- Create: `k8s/zap-scanner/README_KO.md`

- [ ] **Step 1: Add Docker env examples**

In `docker/monolith/deploy-existing-layout.env.example`, add:

```bash
# Optional OWASP ZAP scanner service.
# ZAP should run as a separate container/service.
ZAP_BASE_URL=http://zap-scanner:8080
ZAP_API_KEY=
```

- [ ] **Step 2: Pass ZAP env vars to Docker run**

In `docker/monolith/deploy-existing-layout.sh`, add to `DOCKER_RUN_ARGS`:

```bash
if [ -n "${ZAP_BASE_URL:-}" ]; then
    DOCKER_RUN_ARGS+=(-e "ZAP_BASE_URL=${ZAP_BASE_URL}")
fi
if [ -n "${ZAP_API_KEY:-}" ]; then
    DOCKER_RUN_ARGS+=(-e "ZAP_API_KEY=${ZAP_API_KEY}")
fi
```

- [ ] **Step 3: Create k8s ZAP deployment**

Create `k8s/zap-scanner/deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: zap-scanner
  namespace: jasca
spec:
  replicas: 1
  selector:
    matchLabels:
      app: zap-scanner
  template:
    metadata:
      labels:
        app: zap-scanner
    spec:
      containers:
        - name: zap
          image: ghcr.io/zaproxy/zaproxy:stable
          imagePullPolicy: IfNotPresent
          args:
            - zap.sh
            - -daemon
            - -host
            - 0.0.0.0
            - -port
            - "8080"
            - -config
            - api.disablekey=false
            - -config
            - api.addrs.addr.name=.*
            - -config
            - api.addrs.addr.regex=true
          ports:
            - name: http
              containerPort: 8080
          resources:
            requests:
              cpu: "500m"
              memory: "1Gi"
            limits:
              cpu: "2"
              memory: "3Gi"
```

- [ ] **Step 4: Create k8s service**

Create `k8s/zap-scanner/service.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: zap-scanner
  namespace: jasca
spec:
  selector:
    app: zap-scanner
  ports:
    - name: http
      port: 8080
      targetPort: 8080
```

- [ ] **Step 5: Create kustomization**

Create `k8s/zap-scanner/kustomization.yaml`:

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deployment.yaml
  - service.yaml
```

- [ ] **Step 6: Create Korean README**

Create `k8s/zap-scanner/README_KO.md`:

```markdown
# JASCA ZAP Scanner Kubernetes 배포

ZAP은 JASCA와 별도 Deployment로 실행합니다. JASCA는 `http://zap-scanner:8080`으로 ZAP API를 호출합니다.

## 적용

```bash
kubectl apply -k k8s/zap-scanner
```

## 확인

```bash
kubectl -n jasca get pod,svc -l app=zap-scanner
```

## 주의

- ZAP Service는 외부에 노출하지 않는 것을 권장합니다.
- ZAP egress는 운영 정책에 따라 허용된 진단 대상망으로 제한해야 합니다.
- Active Scan은 대상 서비스에 영향을 줄 수 있으므로 관리자 설정에서 명시적으로 허용한 경우에만 사용하세요.
```

- [ ] **Step 7: Commit**

```powershell
git add docker/monolith/deploy-existing-layout.env.example docker/monolith/deploy-existing-layout.sh k8s/monolith/configmap.yaml k8s/monolith/secret.example.yaml k8s/zap-scanner
git commit -m "Add ZAP deployment assets"
```

---

### Task 12: End-to-End Local Verification

**Files:**
- No code files unless a verification bug is found.

- [ ] **Step 1: Run unit tests**

Run:

```powershell
pnpm --filter @jasca/api test -- zap-parser.service.spec.ts zap-policy.service.spec.ts zap-client.service.spec.ts zap-scan.service.spec.ts
```

Expected: all ZAP test suites PASS.

- [ ] **Step 2: Run builds**

Run:

```powershell
pnpm --filter @jasca/api build
pnpm --filter @jasca/web build
```

Expected: both commands exit 0.

- [ ] **Step 3: Start local ZAP container**

Run:

```powershell
docker network create jasca-zap-test 2>$null
docker rm -f zap-scanner-test 2>$null
docker run -d --name zap-scanner-test --network jasca-zap-test -p 8090:8080 ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
```

Expected: container starts and `docker ps` shows `zap-scanner-test`.

- [ ] **Step 4: Verify ZAP version endpoint**

Run:

```powershell
Invoke-RestMethod -UseBasicParsing http://localhost:8090/JSON/core/view/version/
```

Expected: JSON contains `version`.

- [ ] **Step 5: Rebuild and start JASCA test container**

Run:

```powershell
docker build -f docker/monolith/Dockerfile.rebase -t jasca-offline:zap-phase1-test .
docker rm -f jasca-zap-phase1-test 2>$null
docker run -d --name jasca-zap-phase1-test --network jasca-zap-test -p 3045:3000 -p 3046:3001 -e CORS_ORIGIN="http://localhost:3045" -e PORT=3001 -e JWT_SECRET="jasca_local_zap_secret" -e DB_PASSWORD="jasca_secret" -e REDIS_URL="redis://localhost:6379" jasca-offline:zap-phase1-test
```

Expected: JASCA test container starts and `http://localhost:3045/login` loads.

- [ ] **Step 6: Configure ZAP settings via API**

Run:

```powershell
$login = Invoke-RestMethod -Method Post -Uri 'http://localhost:3046/api/auth/login' -ContentType 'application/json' -Body (@{ email='admin@acme.com'; password='admin123' } | ConvertTo-Json)
$token = $login.accessToken
$zapSettings = @{
  enabled = $true
  zapBaseUrl = 'http://zap-scanner-test:8080'
  apiKey = ''
  connectTimeoutSeconds = 10
  maxScanDurationMinutes = 5
  maxConcurrentScans = 1
  allowBaselineScan = $true
  allowActiveScan = $false
  allowedTargetPatterns = @('example.com')
  blockedTargetPatterns = @()
  defaultRiskThresholdForNotification = 'HIGH'
}
Invoke-RestMethod -Method Put -Uri 'http://localhost:3046/api/settings/zap' -Headers @{ Authorization = "Bearer $token" } -ContentType 'application/json' -Body ($zapSettings | ConvertTo-Json -Depth 5)
```

Expected: settings are saved.

- [ ] **Step 7: Run one ZAP scan through JASCA API**

Run:

```powershell
$body = @{
  targetUrl = 'https://example.com'
  scanMode = 'baseline'
  projectName = 'zap-smoke'
  scanOperationId = [guid]::NewGuid().ToString()
}
$scan = Invoke-RestMethod -Method Post -Uri 'http://localhost:3046/api/scans/scan/zap' -Headers @{ Authorization = "Bearer $token" } -ContentType 'application/json' -Body ($body | ConvertTo-Json)
$scan.id
$scan.sourceType
$scan.summary
```

Expected: `sourceType` is `ZAP_JSON`, scan has a summary, and no unhandled exception occurs.

- [ ] **Step 8: Verify browser UI**

Open:

```text
http://localhost:3045/dashboard/scans
```

Expected:

- Login works with `admin@acme.com / admin123`.
- Scan list shows the ZAP scan.
- Detail page uses ZAP wording and does not show Trivy package-only labels as the primary framing.

- [ ] **Step 9: Commit fixes if verification finds bugs**

If changes are needed:

```powershell
git add <changed-files>
git commit -m "Fix ZAP phase 1 verification issues"
```

If no changes are needed, do not create an empty commit.

---

## Self-Review

Spec coverage:

- Separate ZAP service model: covered by Tasks 11 and 12.
- Admin settings: covered by Tasks 3 and 8.
- URL scan creation: covered by Tasks 7 and 9.
- Baseline/passive workflow: covered by Tasks 5, 6, and 7.
- Raw JSON and normalized result storage: covered by Tasks 2 and 7.
- ZAP-specific list/detail UI: covered by Task 10.
- Safe defaults and target allowlist: covered by Tasks 3 and 4.
- Docker/k8s deployment: covered by Task 11.
- Testing: covered throughout, especially Task 12.

Completion scan:

- This plan intentionally contains no unspecified error handling steps and no vague deferred work.

Type consistency:

- Scanner source type is consistently `ZAP_JSON`.
- Scan mode values are consistently `'baseline' | 'passive' | 'active'`.
- ZAP settings fields are consistently named `zapBaseUrl`, `apiKey`, `allowedTargetPatterns`, and `blockedTargetPatterns`.
