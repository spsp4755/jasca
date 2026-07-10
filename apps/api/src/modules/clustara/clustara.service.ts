import {
    BadRequestException,
    Injectable,
    Logger,
    NotFoundException,
    OnModuleDestroy,
    OnModuleInit,
} from '@nestjs/common';
import { ClustaraDeliveryStatus, ClustaraDeliveryType, ScanArtifactType } from '@prisma/client';
import { request as httpRequest } from 'http';
import { request as httpsRequest } from 'https';
import * as fs from 'fs';
import { PrismaService } from '../../prisma/prisma.service';
import { SettingsService } from '../settings/settings.service';
import { assertProjectAccess, hasAnyRole, RequestUser } from '../../common/authz/access-control';

export type ClustaraAuthType = 'NONE' | 'X_API_KEY' | 'BEARER';
export type ClustaraPayloadType = 'TRIVY' | 'SBOM';

export interface ClustaraSettings {
    enabled: boolean;
    autoSend: boolean;
    baseUrl: string;
    scanPath: string;
    sbomPath: string;
    authType: ClustaraAuthType;
    credential: string;
    defaultClusterId: string;
    scanner: string;
    generator: string;
    timeoutSeconds: number;
    maxAttempts: number;
    verifyTls: boolean;
}

export type SafeClustaraSettings = Omit<ClustaraSettings, 'credential'> & {
    credentialConfigured: boolean;
};

export interface ClustaraRequestInput {
    clusterId: string;
    imageDigest: string;
    scanner?: string;
    generator?: string;
}

export interface QueueDeliveryInput extends Partial<ClustaraRequestInput> {
    clusterId?: string;
    imageDigest?: string;
}

const DEFAULT_SETTINGS: ClustaraSettings = {
    enabled: false,
    autoSend: false,
    baseUrl: '',
    scanPath: '/admin/k8s/security/scans/import',
    sbomPath: '/admin/k8s/security/sboms',
    authType: 'NONE',
    credential: '',
    defaultClusterId: '',
    scanner: 'trivy',
    generator: 'syft',
    timeoutSeconds: 30,
    maxAttempts: 3,
    verifyTls: true,
};

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/i;

export function normalizeClustaraSettings(input: Partial<ClustaraSettings>): ClustaraSettings {
    const authType = ['NONE', 'X_API_KEY', 'BEARER'].includes(String(input.authType))
        ? input.authType as ClustaraAuthType
        : DEFAULT_SETTINGS.authType;

    return {
        ...DEFAULT_SETTINGS,
        ...input,
        baseUrl: String(input.baseUrl || '').trim().replace(/\/+$/, ''),
        scanPath: normalizePath(input.scanPath, DEFAULT_SETTINGS.scanPath),
        sbomPath: normalizePath(input.sbomPath, DEFAULT_SETTINGS.sbomPath),
        authType,
        credential: String(input.credential || '').trim(),
        defaultClusterId: String(input.defaultClusterId || '').trim(),
        scanner: String(input.scanner || DEFAULT_SETTINGS.scanner).trim(),
        generator: String(input.generator || DEFAULT_SETTINGS.generator).trim(),
        timeoutSeconds: clampNumber(input.timeoutSeconds, 5, 300, DEFAULT_SETTINGS.timeoutSeconds),
        maxAttempts: clampNumber(input.maxAttempts, 1, 10, DEFAULT_SETTINGS.maxAttempts),
        enabled: Boolean(input.enabled),
        autoSend: Boolean(input.autoSend),
        verifyTls: input.verifyTls !== false,
    };
}

export function sanitizeClustaraSettings(settings: ClustaraSettings): SafeClustaraSettings {
    const { credential, ...safe } = settings;
    return { ...safe, credentialConfigured: credential.length > 0 };
}

export function buildClustaraRequest(
    settings: ClustaraSettings,
    type: ClustaraPayloadType,
    input: ClustaraRequestInput,
) {
    if (!settings.baseUrl) throw new BadRequestException('Clustara Base URL이 필요합니다.');
    const url = new URL(type === 'TRIVY' ? settings.scanPath : settings.sbomPath, `${settings.baseUrl}/`);
    if (type === 'TRIVY') {
        url.searchParams.set('cluster_id', input.clusterId);
        url.searchParams.set('scanner', input.scanner || settings.scanner);
        url.searchParams.set('image_digest', input.imageDigest);
    } else {
        url.searchParams.set('image_digest', input.imageDigest);
        url.searchParams.set('generator', input.generator || settings.generator);
    }

    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (settings.authType === 'X_API_KEY') headers['X-API-Key'] = settings.credential;
    if (settings.authType === 'BEARER') headers.Authorization = `Bearer ${settings.credential}`;

    return { url, headers };
}

export function deriveImageDigest(explicitDigest: unknown, rawResult: any): string | undefined {
    const candidates = [
        explicitDigest,
        ...(Array.isArray(rawResult?.Metadata?.RepoDigests)
            ? rawResult.Metadata.RepoDigests.map((value: unknown) => String(value).split('@').pop())
            : []),
        rawResult?.Metadata?.ImageID,
    ];
    return candidates.map((value) => String(value || '').trim()).find((value) => DIGEST_PATTERN.test(value));
}

export function isRetryableFailure(status?: number): boolean {
    return status === undefined || status === 408 || status === 429 || status >= 500;
}

function normalizePath(value: unknown, fallback: string): string {
    const path = String(value || fallback).trim();
    return path.startsWith('/') ? path : `/${path}`;
}

function clampNumber(value: unknown, min: number, max: number, fallback: number): number {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? Math.min(max, Math.max(min, Math.trunc(parsed))) : fallback;
}

@Injectable()
export class ClustaraService implements OnModuleInit, OnModuleDestroy {
    private readonly logger = new Logger(ClustaraService.name);
    private worker?: NodeJS.Timeout;

    constructor(
        private readonly prisma: PrismaService,
        private readonly settingsService: SettingsService,
    ) { }

    async onModuleInit() {
        await this.prisma.clustaraDelivery.updateMany({
            where: { status: ClustaraDeliveryStatus.SENDING },
            data: { status: ClustaraDeliveryStatus.PENDING, nextAttemptAt: new Date() },
        });
        this.worker = setInterval(() => {
            this.processNextDelivery().catch((error: Error) => {
                this.logger.warn(`Clustara delivery worker failed: ${error.message}`);
            });
        }, 5000);
        this.worker.unref?.();
    }

    onModuleDestroy() {
        if (this.worker) clearInterval(this.worker);
    }

    async getSettings(maskSecret = true): Promise<ClustaraSettings | SafeClustaraSettings> {
        const stored = await this.settingsService.getRaw('clustara') as Partial<ClustaraSettings> | null;
        const settings = normalizeClustaraSettings(stored || {});
        return maskSecret ? sanitizeClustaraSettings(settings) : settings;
    }

    async updateSettings(input: Partial<ClustaraSettings>): Promise<SafeClustaraSettings> {
        const current = await this.getSettings(false) as ClustaraSettings;
        const submittedCredential = String(input.credential || '').trim();
        const settings = normalizeClustaraSettings({
            ...current,
            ...input,
            credential: submittedCredential && !/^\*+$/.test(submittedCredential)
                ? submittedCredential
                : current.credential,
        });
        this.validateSettings(settings);
        await this.settingsService.set('clustara', settings);
        return sanitizeClustaraSettings(settings);
    }

    async testConnection(input: Partial<ClustaraSettings> = {}) {
        const current = await this.getSettings(false) as ClustaraSettings;
        const settings = normalizeClustaraSettings({
            ...current,
            ...input,
            credential: input.credential || current.credential,
        });
        this.validateSettings(settings, false);
        const url = new URL(settings.baseUrl);
        const startedAt = Date.now();
        const result = await this.sendHttp(url, 'HEAD', {}, '', settings);
        return {
            success: true,
            reachable: true,
            authenticationVerified: false,
            status: result.status,
            durationMs: Date.now() - startedAt,
            message: 'Clustara DNS/TCP/TLS 연결에 성공했습니다. Import 인증은 실제 전송 시 검증됩니다.',
        };
    }

    async queueDelivery(
        scanResultId: string,
        type: ClustaraPayloadType,
        input: QueueDeliveryInput,
        currentUser?: RequestUser,
    ) {
        const scan = await this.prisma.scanResult.findUnique({
            where: { id: scanResultId },
            include: { project: true, artifacts: true },
        });
        if (!scan) throw new NotFoundException('스캔 결과를 찾을 수 없습니다.');
        if (currentUser && !hasAnyRole(currentUser, ['SECURITY_ADMIN'])) {
            assertProjectAccess(currentUser, scan.project);
        }

        const settings = await this.getSettings(false) as ClustaraSettings;
        const clusterId = String(input.clusterId || settings.defaultClusterId).trim();
        const imageDigest = deriveImageDigest(input.imageDigest || scan.imageDigest, scan.rawResult);
        if (!clusterId) throw new BadRequestException('Clustara cluster_id가 필요합니다.');
        if (!imageDigest) {
            throw new BadRequestException('image_digest는 sha256: 뒤에 64자리 16진수가 있어야 합니다.');
        }
        if (type === 'SBOM' && !scan.artifacts.some((artifact) => artifact.type === ScanArtifactType.CYCLONEDX_JSON)) {
            throw new BadRequestException('이 스캔에 저장된 CycloneDX SBOM이 없습니다.');
        }

        const deliveryType = type as ClustaraDeliveryType;
        const unique = { scanResultId, type: deliveryType, clusterId, imageDigest };
        const existing = await this.prisma.clustaraDelivery.findUnique({
            where: { scanResultId_type_clusterId_imageDigest: unique },
        });
        if (existing) return existing;

        return this.prisma.clustaraDelivery.create({
            data: {
                ...unique,
                scanner: type === 'TRIVY' ? String(input.scanner || settings.scanner).trim() : null,
                generator: type === 'SBOM' ? String(input.generator || settings.generator).trim() : null,
                maxAttempts: settings.maxAttempts,
            },
        });
    }

    async queueAutomatic(scanResultId: string) {
        const settings = await this.getSettings(false) as ClustaraSettings;
        if (!settings.enabled || !settings.autoSend || !settings.defaultClusterId) return [];

        const scan = await this.prisma.scanResult.findUnique({
            where: { id: scanResultId },
            include: { artifacts: true },
        });
        if (!scan || !this.isTrivyResult(scan.sourceType, scan.rawResult)) return [];
        const imageDigest = deriveImageDigest(scan.imageDigest, scan.rawResult);
        if (!imageDigest) return [];

        const deliveries = [await this.queueDelivery(scanResultId, 'TRIVY', {
            clusterId: settings.defaultClusterId,
            imageDigest,
            scanner: settings.scanner,
        })];
        if (scan.artifacts.some((artifact) => artifact.type === ScanArtifactType.CYCLONEDX_JSON)) {
            deliveries.push(await this.queueDelivery(scanResultId, 'SBOM', {
                clusterId: settings.defaultClusterId,
                imageDigest,
                generator: settings.generator,
            }));
        }
        return deliveries;
    }

    async listDeliveries(limit = 50) {
        return this.prisma.clustaraDelivery.findMany({
            include: { scanResult: { select: { id: true, imageRef: true, artifactName: true, projectId: true } } },
            orderBy: { createdAt: 'desc' },
            take: Math.min(200, Math.max(1, limit)),
        });
    }

    async getDeliveriesForScan(scanResultId: string, currentUser?: RequestUser) {
        const scan = await this.prisma.scanResult.findUnique({
            where: { id: scanResultId },
            include: { project: true },
        });
        if (!scan) throw new NotFoundException('스캔 결과를 찾을 수 없습니다.');
        if (currentUser && !hasAnyRole(currentUser, ['SECURITY_ADMIN'])) {
            assertProjectAccess(currentUser, scan.project);
        }
        return this.prisma.clustaraDelivery.findMany({
            where: { scanResultId },
            orderBy: { createdAt: 'desc' },
        });
    }

    async retryDelivery(id: string, currentUser?: RequestUser) {
        const delivery = await this.prisma.clustaraDelivery.findUnique({
            where: { id },
            include: { scanResult: { include: { project: true } } },
        });
        if (!delivery) throw new NotFoundException('Clustara 전송 이력을 찾을 수 없습니다.');
        if (currentUser && !hasAnyRole(currentUser, ['SECURITY_ADMIN'])) {
            assertProjectAccess(currentUser, delivery.scanResult.project);
        }
        return this.prisma.clustaraDelivery.update({
            where: { id },
            data: {
                status: ClustaraDeliveryStatus.PENDING,
                attempts: 0,
                nextAttemptAt: new Date(),
                lastError: null,
                httpStatus: null,
            },
        });
    }

    async sendPayload(
        settings: ClustaraSettings,
        type: ClustaraPayloadType,
        input: ClustaraRequestInput,
        body: string,
    ) {
        const request = buildClustaraRequest(settings, type, input);
        return this.sendHttp(request.url, 'POST', request.headers, body, settings);
    }

    private async processNextDelivery() {
        const due = await this.prisma.clustaraDelivery.findFirst({
            where: { status: ClustaraDeliveryStatus.PENDING, nextAttemptAt: { lte: new Date() } },
            orderBy: { nextAttemptAt: 'asc' },
            select: { id: true },
        });
        if (due) await this.processDelivery(due.id);
    }

    async processDelivery(id: string) {
        const claimed = await this.prisma.clustaraDelivery.updateMany({
            where: { id, status: ClustaraDeliveryStatus.PENDING },
            data: { status: ClustaraDeliveryStatus.SENDING, startedAt: new Date(), attempts: { increment: 1 } },
        });
        if (claimed.count !== 1) return null;

        const delivery = await this.prisma.clustaraDelivery.findUnique({
            where: { id },
            include: { scanResult: { include: { artifacts: true } } },
        });
        if (!delivery) return null;

        try {
            const settings = await this.getSettings(false) as ClustaraSettings;
            this.validateSettings(settings);
            const type = delivery.type as ClustaraPayloadType;
            const body = type === 'TRIVY'
                ? JSON.stringify(delivery.scanResult.rawResult)
                : await this.readSbom(delivery.scanResult.artifacts);
            const response = await this.sendPayload(settings, type, {
                clusterId: delivery.clusterId,
                imageDigest: delivery.imageDigest,
                scanner: delivery.scanner || settings.scanner,
                generator: delivery.generator || settings.generator,
            }, body);

            if (response.status >= 200 && response.status < 300) {
                return this.prisma.clustaraDelivery.update({
                    where: { id },
                    data: {
                        status: ClustaraDeliveryStatus.SUCCESS,
                        httpStatus: response.status,
                        responseSummary: this.cleanResponse(response.body),
                        lastError: null,
                        succeededAt: new Date(),
                    },
                });
            }
            return this.recordFailure(delivery, `HTTP ${response.status}: ${this.cleanResponse(response.body)}`, response.status);
        } catch (error) {
            return this.recordFailure(delivery, (error as Error).message);
        }
    }

    private async recordFailure(delivery: any, message: string, httpStatus?: number) {
        const retry = isRetryableFailure(httpStatus) && delivery.attempts < delivery.maxAttempts;
        const delayMinutes = delivery.attempts <= 1 ? 1 : 5;
        return this.prisma.clustaraDelivery.update({
            where: { id: delivery.id },
            data: {
                status: retry ? ClustaraDeliveryStatus.PENDING : ClustaraDeliveryStatus.FAILED,
                httpStatus: httpStatus || null,
                lastError: this.cleanResponse(message),
                nextAttemptAt: retry ? new Date(Date.now() + delayMinutes * 60_000) : delivery.nextAttemptAt,
            },
        });
    }

    private async readSbom(artifacts: Array<{ type: ScanArtifactType; filePath: string }>) {
        const artifact = artifacts.find((item) => item.type === ScanArtifactType.CYCLONEDX_JSON);
        if (!artifact) throw new Error('저장된 CycloneDX SBOM이 없습니다.');
        return fs.promises.readFile(artifact.filePath, 'utf-8');
    }

    private sendHttp(
        url: URL,
        method: 'HEAD' | 'POST',
        headers: Record<string, string>,
        body: string,
        settings: ClustaraSettings,
    ): Promise<{ status: number; body: string }> {
        return new Promise((resolve, reject) => {
            const transport = url.protocol === 'https:' ? httpsRequest : httpRequest;
            const request = transport(url, {
                method,
                headers: {
                    ...headers,
                    ...(body ? { 'Content-Length': String(Buffer.byteLength(body)) } : {}),
                },
                timeout: settings.timeoutSeconds * 1000,
                ...(url.protocol === 'https:' ? { rejectUnauthorized: settings.verifyTls } : {}),
            }, (response) => {
                const chunks: Buffer[] = [];
                let received = 0;
                response.on('data', (chunk) => {
                    received += chunk.length;
                    if (received <= 1000) chunks.push(Buffer.from(chunk));
                });
                response.on('end', () => resolve({
                    status: response.statusCode || 0,
                    body: Buffer.concat(chunks).toString('utf-8').slice(0, 1000),
                }));
            });
            request.on('timeout', () => request.destroy(new Error(`Clustara 요청 시간이 ${settings.timeoutSeconds}초를 초과했습니다.`)));
            request.on('error', reject);
            if (body) request.write(body);
            request.end();
        });
    }

    private validateSettings(settings: ClustaraSettings, requireCredential = true) {
        let url: URL;
        try {
            url = new URL(settings.baseUrl);
        } catch {
            throw new BadRequestException('올바른 Clustara Base URL이 필요합니다.');
        }
        if (!['http:', 'https:'].includes(url.protocol)) {
            throw new BadRequestException('Clustara Base URL은 http 또는 https만 사용할 수 있습니다.');
        }
        if (requireCredential && settings.authType !== 'NONE' && !settings.credential) {
            throw new BadRequestException('선택한 인증 방식의 API Key 또는 Token이 필요합니다.');
        }
    }

    private isTrivyResult(sourceType: string, rawResult: any) {
        if (['CHECKOV_JSON', 'ZAP_JSON', 'SARIF'].includes(sourceType)) return false;
        const scanner = String(rawResult?.Metadata?.JascaScanEvidence?.scanner || '').toLowerCase();
        return !scanner || scanner === 'trivy';
    }

    private cleanResponse(value: string) {
        return String(value || '').replace(/<[^>]*>/g, '').slice(0, 1000);
    }
}
