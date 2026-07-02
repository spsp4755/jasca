import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

type GitProvider = 'GITHUB' | 'GITLAB' | 'BITBUCKET' | 'AZURE_DEVOPS';
type IssueTrackerProvider = 'JIRA' | 'LINEAR' | 'GITHUB_ISSUES' | 'GITLAB_ISSUES' | 'AZURE_DEVOPS' | 'ASANA';

export interface CreateGitIntegrationDto {
    organizationId: string;
    provider: GitProvider;
    name: string;
    baseUrl?: string;
    apiToken: string;
    defaultBranch?: string;
}

export interface CreateIssueTrackerDto {
    organizationId: string;
    provider: IssueTrackerProvider;
    name: string;
    baseUrl: string;
    apiToken: string;
    projectKey?: string;
    autoCreateIssues?: boolean;
}

export interface LinkIssueDto {
    integrationId: string;
    scanVulnerabilityId: string;
    externalId: string;
    externalUrl: string;
    status?: string;
}

@Injectable()
export class DevOpsIntegrationService {
    private readonly logger = new Logger(DevOpsIntegrationService.name);

    constructor(private readonly prisma: PrismaService) { }

    /**
     * Create a new Git integration
     */
    async createGitIntegration(dto: CreateGitIntegrationDto) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const prismaAny = this.prisma as any;

        return prismaAny.gitIntegration?.create({
            data: {
                organizationId: dto.organizationId,
                provider: dto.provider,
                name: dto.name,
                baseUrl: dto.baseUrl,
                apiToken: dto.apiToken, // TODO: Encrypt before storage
                defaultBranch: dto.defaultBranch || 'main',
            },
        });
    }

    /**
     * Get Git integrations for an organization
     */
    async getGitIntegrations(organizationId: string) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const prismaAny = this.prisma as any;

        return (
            prismaAny.gitIntegration?.findMany({
                where: { organizationId },
                include: { repositories: true },
            }) || []
        );
    }

    /**
     * Link a repository to a project
     */
    async linkRepository(
        integrationId: string,
        projectId: string,
        repoUrl: string,
        repoOwner: string,
        repoName: string,
    ) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const prismaAny = this.prisma as any;

        return prismaAny.gitRepository?.create({
            data: {
                integrationId,
                projectId,
                repoUrl,
                repoOwner,
                repoName,
            },
        });
    }

    /**
     * Create an Issue Tracker integration
     */
    async createIssueTrackerIntegration(dto: CreateIssueTrackerDto) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const prismaAny = this.prisma as any;

        return prismaAny.issueTrackerIntegration?.create({
            data: {
                organizationId: dto.organizationId,
                provider: dto.provider,
                name: dto.name,
                baseUrl: dto.baseUrl,
                apiToken: dto.apiToken, // TODO: Encrypt before storage
                projectKey: dto.projectKey,
                autoCreateIssues: dto.autoCreateIssues || false,
            },
        });
    }

    /**
     * Get Issue Tracker integrations for an organization
     */
    async getIssueTrackerIntegrations(organizationId: string) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const prismaAny = this.prisma as any;

        return (
            prismaAny.issueTrackerIntegration?.findMany({
                where: { organizationId },
            }) || []
        );
    }

    /**
     * Link a vulnerability to an external issue
     */
    async linkIssue(dto: LinkIssueDto) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const prismaAny = this.prisma as any;

        return prismaAny.linkedIssue?.create({
            data: {
                integrationId: dto.integrationId,
                scanVulnerabilityId: dto.scanVulnerabilityId,
                externalId: dto.externalId,
                externalUrl: dto.externalUrl,
                status: dto.status,
            },
        });
    }

    /**
     * Get linked issues for a vulnerability
     */
    async getLinkedIssues(scanVulnerabilityId: string) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const prismaAny = this.prisma as any;

        return (
            prismaAny.linkedIssue?.findMany({
                where: { scanVulnerabilityId },
                include: { integration: true },
            }) || []
        );
    }

    /**
     * Create issue in external tracker (stub - implementation depends on provider)
     */
    async createExternalIssue(
        integrationId: string,
        scanVulnerabilityId: string,
        title: string,
        description: string,
    ): Promise<{ externalId: string; externalUrl: string }> {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const prismaAny = this.prisma as any;

        const integration = await prismaAny.issueTrackerIntegration?.findUnique({
            where: { id: integrationId },
        });

        if (!integration) {
            throw new BadRequestException('Integration not found');
        }

        // In a real implementation, this would call the external API
        // For now, generate a mock external ID
        const externalId = `MOCK-${Date.now()}`;
        const externalUrl = `${integration.baseUrl}/issues/${externalId}`;

        // Create the linked issue record
        await this.linkIssue({
            integrationId,
            scanVulnerabilityId,
            externalId,
            externalUrl,
            status: 'OPEN',
        });

        this.logger.log(
            `Created external issue ${externalId} for vulnerability ${scanVulnerabilityId}`,
        );

        return { externalId, externalUrl };
    }

    /**
     * Sync issue status from external tracker
     */
    async syncIssueStatus(linkedIssueId: string): Promise<void> {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const prismaAny = this.prisma as any;

        const linkedIssue = await prismaAny.linkedIssue?.findUnique({
            where: { id: linkedIssueId },
            include: { integration: true },
        });

        if (!linkedIssue) {
            throw new BadRequestException('Linked issue not found');
        }

        // In a real implementation, fetch status from external API
        // For now, just log the sync attempt
        this.logger.log(
            `Syncing status for issue ${linkedIssue.externalId} from ${linkedIssue.integration.provider}`,
        );
    }
}
