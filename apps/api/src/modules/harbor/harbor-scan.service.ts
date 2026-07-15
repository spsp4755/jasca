import {
    BadRequestException,
    ForbiddenException,
    Injectable,
    UnauthorizedException,
} from '@nestjs/common';
import { HarborScanJobStatus, SourceType } from '@prisma/client';
import { createHash, timingSafeEqual } from 'crypto';
import { assertProjectAccess, RequestUser } from '../../common/authz/access-control';
import { PrismaService } from '../../prisma/prisma.service';
import { ScansService } from '../scans/scans.service';
import { TrivyScanService } from '../scans/services/trivy-scan.service';
import { SettingsService } from '../settings/settings.service';
import { HarborSettings, normalizeHarborSettings } from './harbor.service';

export type HarborScanTrigger = 'manual' | 'webhook';

export interface HarborManualScanInput {
    projectId: string;
    imageRef: string;
    imageDigest: string;
    tag?: string;
}

interface HarborScanInput extends HarborManualScanInput {
    trigger: HarborScanTrigger;
}

export interface HarborPushArtifactPayload {
    type?: string;
    occur_at?: number;
    operator?: string;
    event_data?: {
        resources?: Array<{
            digest?: string;
            tag?: string;
            resource_url?: string;
        }>;
        repository?: {
            date_created?: number;
            name?: string;
            namespace?: string;
            repo_full_name?: string;
            repo_type?: string;
        };
    };
}

export interface HarborScanResult {
    duplicate: boolean;
    scan?: any;
}

export interface HarborWebhookResult {
    accepted: boolean;
    duplicate?: boolean;
}

const IMAGE_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/i;
const configuredRecentWindowMs = Number(process.env.HARBOR_SCAN_DEDUP_TTL_MS);
const RECENT_SCAN_WINDOW_MS = Number.isFinite(configuredRecentWindowMs) && configuredRecentWindowMs > 0
    ? configuredRecentWindowMs
    : 10 * 60 * 1000;
const configuredStaleJobTtlMs = Number(process.env.HARBOR_SCAN_JOB_STALE_TTL_MS);
const STALE_JOB_TTL_MS = Number.isFinite(configuredStaleJobTtlMs) && configuredStaleJobTtlMs > 0
    ? configuredStaleJobTtlMs
    : 24 * 60 * 60 * 1000;
const STALE_JOB_ERROR = 'Harbor scan job exceeded its stale TTL';

@Injectable()
export class HarborScanService {
    constructor(
        private readonly settingsService: SettingsService,
        private readonly trivyScanService: TrivyScanService,
        private readonly scansService: ScansService,
        private readonly prisma: PrismaService,
    ) {}

    async handleWebhook(
        authorization: string | undefined,
        payload: HarborPushArtifactPayload,
    ): Promise<HarborWebhookResult> {
        const settings = await this.getSettings();
        if (!settings.enabled || !settings.autoScanOnPush) {
            throw new ForbiddenException('Harbor push scanning is disabled');
        }

        this.assertWebhookAuthorization(authorization, settings.webhookSecret);
        if (payload?.type !== 'PUSH_ARTIFACT') {
            throw new ForbiddenException('Unsupported Harbor webhook event');
        }
        if (!settings.defaultProjectId) {
            throw new BadRequestException('A default JASCA project is required for Harbor webhooks');
        }

        const repository = payload.event_data?.repository;
        const namespace = String(repository?.namespace || '').trim();
        const repositoryName = String(repository?.name || '').trim();
        if (!namespace || !repositoryName) {
            throw new BadRequestException('Harbor repository namespace and name are required');
        }
        this.assertAllowedProject(settings, namespace);

        const resources = payload.event_data?.resources;
        if (!Array.isArray(resources) || resources.length === 0) {
            throw new BadRequestException('Harbor push payload is missing an image Digest');
        }

        const scanInputs = resources.map((resource): HarborScanInput => {
            const imageDigest = this.normalizeDigest(resource?.digest);
            const tag = String(resource?.tag || '').trim() || undefined;
            return {
                projectId: settings.defaultProjectId,
                imageRef: this.webhookImageReference(settings, namespace, repositoryName, resource?.resource_url, tag),
                imageDigest,
                tag,
                trigger: 'webhook',
            };
        });

        const results: HarborScanResult[] = [];
        for (const input of scanInputs) {
            results.push(await this.scanWithSettings(input, settings));
        }

        return results.every((result) => result.duplicate)
            ? { accepted: true, duplicate: true }
            : { accepted: true };
    }

    async scan(input: HarborManualScanInput, currentUser: RequestUser): Promise<HarborScanResult> {
        return this.scanWithSettings(
            { ...input, trigger: 'manual' },
            await this.getSettings(),
            currentUser,
        );
    }

    private async scanWithSettings(
        input: HarborScanInput,
        settings: HarborSettings,
        currentUser?: RequestUser,
    ): Promise<HarborScanResult> {
        if (!settings.enabled) {
            throw new ForbiddenException('Harbor integration is disabled');
        }

        const projectId = String(input.projectId || '').trim();
        if (!projectId) {
            throw new BadRequestException('A JASCA project is required for Harbor scans');
        }

        const imageRef = this.normalizeImageReference(input.imageRef);
        const imageDigest = this.normalizeDigest(input.imageDigest);
        const harborProject = this.harborProjectForImage(settings, imageRef);
        this.assertAllowedProject(settings, harborProject);

        const project = await this.prisma.project.findUnique({
            where: { id: projectId },
            select: { id: true, organizationId: true },
        });
        if (!project) {
            throw new BadRequestException(`Project with ID ${projectId} not found`);
        }
        if (input.trigger === 'manual') {
            assertProjectAccess(currentUser, project);
        }

        const immutableImageRef = `${this.repositoryReference(imageRef)}@${imageDigest}`;
        const job = await this.claimJob({
            projectId,
            imageRef,
            imageDigest,
            tag: input.tag,
            trigger: input.trigger,
        });
        if (!job) {
            return { duplicate: true };
        }

        try {
            const { rawResult } = await this.trivyScanService.scanImageReference(immutableImageRef, {
                registryUsername: settings.username,
                registryPassword: settings.password,
            });
            rawResult.Metadata = rawResult.Metadata || {};
            rawResult.Metadata.JascaScanEvidence = rawResult.Metadata.JascaScanEvidence || {};
            rawResult.Metadata.JascaScanEvidence.harbor = {
                trigger: input.trigger,
                imageRef,
                imageDigest,
                ...(input.tag ? { tag: input.tag } : {}),
            };

            const uploadDto = {
                sourceType: SourceType.TRIVY_JSON,
                imageRef,
                imageDigest,
                tag: input.tag,
            };
            const sourceInfo = {
                ...(currentUser ? { uploadedById: currentUser.id } : {}),
                userAgent: `Harbor ${input.trigger} scan`,
            };
            const scan = currentUser
                ? await this.scansService.uploadScan(projectId, uploadDto, rawResult, sourceInfo, currentUser)
                : await this.scansService.uploadScan(projectId, uploadDto, rawResult, sourceInfo);

            const completed = await this.prisma.harborScanJob.updateMany({
                where: {
                    projectId,
                    imageDigest,
                    status: HarborScanJobStatus.RUNNING,
                    startedAt: job.startedAt,
                },
                data: {
                    status: HarborScanJobStatus.COMPLETED,
                    scanResultId: scan?.id || null,
                    error: null,
                    completedAt: new Date(),
                },
            });
            if (completed.count !== 1) {
                throw new Error('Harbor scan job ownership was lost before completion');
            }

            return { duplicate: false, scan };
        } catch (error) {
            await this.prisma.harborScanJob.updateMany({
                where: {
                    projectId,
                    imageDigest,
                    status: HarborScanJobStatus.RUNNING,
                    startedAt: job.startedAt,
                },
                data: {
                    status: HarborScanJobStatus.FAILED,
                    error: this.redactJobError(error, settings),
                    completedAt: new Date(),
                },
            });
            throw error;
        }
    }

    private async claimJob(input: HarborScanInput): Promise<{ startedAt: Date } | null> {
        const startedAt = new Date();
        const runningJob = {
            imageRef: input.imageRef,
            tag: input.tag || null,
            trigger: input.trigger,
            status: HarborScanJobStatus.RUNNING,
            scanResultId: null,
            error: null,
            startedAt,
            completedAt: null,
        };

        try {
            await this.prisma.harborScanJob.create({
                data: {
                    projectId: input.projectId,
                    imageDigest: input.imageDigest,
                    ...runningJob,
                },
                select: { id: true },
            });
            return { startedAt };
        } catch (error) {
            if (!this.isUniqueConstraintError(error)) {
                throw error;
            }
        }

        const now = new Date();
        await this.prisma.harborScanJob.updateMany({
            where: {
                projectId: input.projectId,
                imageDigest: input.imageDigest,
                status: HarborScanJobStatus.RUNNING,
                startedAt: { lte: new Date(now.getTime() - STALE_JOB_TTL_MS) },
            },
            data: {
                status: HarborScanJobStatus.FAILED,
                error: STALE_JOB_ERROR,
                completedAt: now,
            },
        });

        const claimed = await this.prisma.harborScanJob.updateMany({
            where: {
                projectId: input.projectId,
                imageDigest: input.imageDigest,
                OR: [
                    { status: HarborScanJobStatus.FAILED },
                    {
                        status: HarborScanJobStatus.COMPLETED,
                        completedAt: { lte: new Date(now.getTime() - RECENT_SCAN_WINDOW_MS) },
                    },
                ],
            },
            data: runningJob,
        });

        return claimed.count === 1 ? { startedAt } : null;
    }

    private isUniqueConstraintError(error: unknown): boolean {
        return typeof error === 'object'
            && error !== null
            && 'code' in error
            && error.code === 'P2002';
    }

    private redactJobError(error: unknown, settings: HarborSettings): string {
        let message = error instanceof Error && error.message
            ? error.message
            : 'Harbor scan failed';
        const credentials = [settings.username, settings.password]
            .filter((value): value is string => Boolean(value));
        for (const credential of credentials) {
            message = message.split(credential).join('[REDACTED]');
            const encodedCredential = encodeURIComponent(credential);
            if (encodedCredential !== credential) {
                message = message.split(encodedCredential).join('[REDACTED]');
            }
        }
        return message.slice(0, 2000);
    }

    private async getSettings(): Promise<HarborSettings> {
        return normalizeHarborSettings(
            await this.settingsService.getRaw('harbor') as Partial<HarborSettings> || {},
        );
    }

    private assertWebhookAuthorization(authorization: string | undefined, webhookSecret: string): void {
        const prefix = 'Bearer ';
        const suppliedSecret = authorization?.startsWith(prefix)
            ? authorization.slice(prefix.length)
            : '';
        const expectedHash = createHash('sha256').update(webhookSecret).digest();
        const suppliedHash = createHash('sha256').update(suppliedSecret).digest();

        if (!webhookSecret || !timingSafeEqual(expectedHash, suppliedHash)) {
            throw new UnauthorizedException('Invalid Harbor webhook authorization');
        }
    }

    private assertAllowedProject(settings: HarborSettings, project: string): void {
        if (settings.allowedProjects.length > 0 && !settings.allowedProjects.includes(project)) {
            throw new ForbiddenException('Harbor project is not allowed');
        }
    }

    private webhookImageReference(
        settings: HarborSettings,
        namespace: string,
        repositoryName: string,
        resourceUrl: string | undefined,
        tag: string | undefined,
    ): string {
        if (resourceUrl?.trim()) {
            return this.normalizeImageReference(resourceUrl);
        }

        let registry: string;
        try {
            registry = new URL(settings.baseUrl).host;
        } catch {
            throw new BadRequestException('Harbor base URL is invalid');
        }
        const usableTag = tag && /^[\w][\w.-]{0,127}$/.test(tag) ? `:${tag}` : '';
        return `${registry}/${namespace}/${repositoryName}${usableTag}`;
    }

    private normalizeImageReference(value: string): string {
        const imageRef = String(value || '')
            .trim()
            .replace(/^https?:\/\//i, '')
            .replace(/[?#].*$/, '')
            .replace(/\/+$/, '');
        if (!imageRef || /\s/.test(imageRef) || !imageRef.includes('/')) {
            throw new BadRequestException('A valid Harbor image reference is required');
        }

        const firstSlash = imageRef.indexOf('/');
        const firstAt = imageRef.indexOf('@');
        if (firstAt !== -1 && firstAt < firstSlash) {
            throw new BadRequestException('Harbor image references must not contain credentials');
        }
        return imageRef;
    }

    private harborProjectForImage(settings: HarborSettings, imageRef: string): string {
        let registry: string;
        try {
            registry = new URL(settings.baseUrl).host;
        } catch {
            throw new BadRequestException('Harbor base URL is invalid');
        }

        const firstSlash = imageRef.indexOf('/');
        if (imageRef.slice(0, firstSlash).toLowerCase() !== registry.toLowerCase()) {
            throw new ForbiddenException('Image reference is outside the configured Harbor registry');
        }
        const project = imageRef.slice(firstSlash + 1).split('/')[0];
        if (!project) {
            throw new BadRequestException('Harbor image reference is missing a project');
        }
        return project;
    }

    private repositoryReference(imageRef: string): string {
        const digestSeparator = imageRef.lastIndexOf('@');
        const withoutDigest = digestSeparator > imageRef.lastIndexOf('/')
            ? imageRef.slice(0, digestSeparator)
            : imageRef;
        const lastSlash = withoutDigest.lastIndexOf('/');
        const tagSeparator = withoutDigest.lastIndexOf(':');
        return tagSeparator > lastSlash ? withoutDigest.slice(0, tagSeparator) : withoutDigest;
    }

    private normalizeDigest(value: string | undefined): string {
        const digest = String(value || '').trim();
        if (!IMAGE_DIGEST_PATTERN.test(digest)) {
            throw new BadRequestException('Harbor push payload is missing a valid image Digest');
        }
        return digest.toLowerCase();
    }
}
