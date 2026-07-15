import {
    BadRequestException,
    ForbiddenException,
    Inject,
    Injectable,
    Logger,
    NotFoundException,
    OnModuleDestroy,
    OnModuleInit,
} from '@nestjs/common';
import { AiExecution, AiExecutionStatus, Prisma } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { NotificationsService } from '../notifications/notifications.service';

export const AI_JOB_EXECUTOR = Symbol('AI_JOB_EXECUTOR');

export interface AiJobExecutor {
    runExecution(executionId: string): Promise<void>;
}

export interface AiJobActor {
    id: string;
    organizationId?: string;
    roles: string[];
    isApiToken: boolean;
    permissions: string[];
    apiTokenId?: string;
}

const ACTIVE_STATUSES: AiExecutionStatus[] = [
    AiExecutionStatus.QUEUED,
    AiExecutionStatus.RUNNING,
];
const TERMINAL_NOTIFICATION_STATUSES: AiExecutionStatus[] = [
    AiExecutionStatus.SUCCESS,
    AiExecutionStatus.ERROR,
    AiExecutionStatus.TIMEOUT,
];
const WORKER_INTERVAL_MS = 5_000;
const HEARTBEAT_INTERVAL_MS = 30_000;
const STALE_JOB_MS = 15 * 60_000;
const NOTIFICATION_LEASE_MS = 60_000;
const API_TOKEN_USER_ID_PREFIX = 'api-token:';

@Injectable()
export class AiJobService implements OnModuleInit, OnModuleDestroy {
    private readonly logger = new Logger(AiJobService.name);
    private worker?: NodeJS.Timeout;

    constructor(
        private readonly prisma: PrismaService,
        private readonly notifications: NotificationsService,
        @Inject(AI_JOB_EXECUTOR)
        private readonly executor: AiJobExecutor,
    ) {}

    async onModuleInit(): Promise<void> {
        await this.recoverStaleJobs();
        this.worker = setInterval(() => {
            this.processNextJob().catch((error: Error) => {
                this.logger.warn(`AI job worker failed: ${error.message}`);
            });
        }, WORKER_INTERVAL_MS);
        this.worker.unref?.();
    }

    onModuleDestroy(): void {
        if (this.worker) clearInterval(this.worker);
    }

    enqueue(action: string, context: Record<string, unknown>, actor: AiJobActor) {
        return this.prisma.aiExecution.create({
            data: {
                action,
                context: context as Prisma.JsonObject,
                status: AiExecutionStatus.QUEUED,
                userId: actor.id,
                organizationId: actor.organizationId || null,
            },
        });
    }

    async getJob(id: string, actor: AiJobActor): Promise<AiExecution> {
        const execution = await this.prisma.aiExecution.findUnique({ where: { id } });
        if (!execution) throw new NotFoundException('AI execution not found');

        await this.assertCanAccess(execution, actor);
        return execution;
    }

    async cancel(id: string, actor: AiJobActor): Promise<AiExecution> {
        const execution = await this.getJob(id, actor);
        if (!ACTIVE_STATUSES.includes(execution.status)) {
            throw new BadRequestException('Only active AI jobs can be cancelled');
        }

        const completedAt = new Date();
        const cancelled = await this.prisma.aiExecution.updateMany({
            where: { id, status: { in: ACTIVE_STATUSES } },
            data: { status: AiExecutionStatus.CANCELLED, completedAt },
        });
        if (cancelled.count !== 1) return this.getJob(id, actor);

        return {
            ...execution,
            status: AiExecutionStatus.CANCELLED,
            completedAt,
        };
    }

    async processNextJob(): Promise<AiExecution | null> {
        await this.recoverStaleJobs();
        await this.processPendingNotification();

        const queued = await this.prisma.aiExecution.findFirst({
            where: { status: AiExecutionStatus.QUEUED },
            orderBy: { createdAt: 'asc' },
            select: { id: true },
        });
        if (!queued) return null;

        const claimed = await this.prisma.aiExecution.updateMany({
            where: { id: queued.id, status: AiExecutionStatus.QUEUED },
            data: {
                status: AiExecutionStatus.RUNNING,
                startedAt: new Date(),
                updatedAt: new Date(),
                attempts: { increment: 1 },
            },
        });
        if (claimed.count !== 1) return null;

        const heartbeat = this.startHeartbeat(queued.id);
        try {
            await this.executor.runExecution(queued.id);
        } catch (error) {
            await this.prisma.aiExecution.updateMany({
                where: { id: queued.id, status: AiExecutionStatus.RUNNING },
                data: {
                    status: AiExecutionStatus.ERROR,
                    error: error instanceof Error ? error.message : 'Unknown AI execution error',
                    completedAt: new Date(),
                },
            });
        } finally {
            clearInterval(heartbeat);
        }

        const execution = await this.prisma.aiExecution.findUnique({ where: { id: queued.id } });
        if (!execution) return null;

        await this.createTerminalNotification(execution);
        return execution;
    }

    private recoverStaleJobs() {
        return this.prisma.aiExecution.updateMany({
            where: {
                status: AiExecutionStatus.RUNNING,
                updatedAt: { lt: new Date(Date.now() - STALE_JOB_MS) },
            },
            data: {
                status: AiExecutionStatus.QUEUED,
                startedAt: null,
            },
        });
    }

    private startHeartbeat(id: string): NodeJS.Timeout {
        const heartbeat = setInterval(() => {
            this.prisma.aiExecution.updateMany({
                where: { id, status: AiExecutionStatus.RUNNING },
                data: { updatedAt: new Date() },
            }).catch((error: Error) => {
                this.logger.warn(`Failed to heartbeat AI job ${id}: ${error.message}`);
            });
        }, HEARTBEAT_INTERVAL_MS);
        heartbeat.unref?.();
        return heartbeat;
    }

    private async processPendingNotification(): Promise<void> {
        const leaseExpiredAt = new Date(Date.now() - NOTIFICATION_LEASE_MS);
        const pending = await this.prisma.aiExecution.findFirst({
            where: {
                attempts: { gt: 0 },
                status: { in: TERMINAL_NOTIFICATION_STATUSES },
                userId: { not: null },
                NOT: { userId: { startsWith: API_TOKEN_USER_ID_PREFIX } },
                notificationSentAt: null,
                OR: [
                    { notificationClaimedAt: null },
                    { notificationClaimedAt: { lt: leaseExpiredAt } },
                ],
            },
            orderBy: { completedAt: 'asc' },
        });
        if (pending) await this.createTerminalNotification(pending);
    }

    private async assertCanAccess(
        execution: Pick<AiExecution, 'userId' | 'organizationId'>,
        actor: AiJobActor,
    ): Promise<void> {
        if (execution.userId === actor.id) return;
        if (!actor.isApiToken && actor.roles.includes('SYSTEM_ADMIN')) return;

        if (
            !actor.isApiToken
            && actor.roles.includes('ORG_ADMIN')
            && actor.organizationId
        ) {
            if (execution.organizationId === actor.organizationId) return;

            if (
                !execution.organizationId
                && execution.userId
                && !execution.userId.startsWith(API_TOKEN_USER_ID_PREFIX)
            ) {
                const owner = await this.prisma.user.findUnique({
                    where: { id: execution.userId },
                    select: { organizationId: true },
                });
                if (owner?.organizationId === actor.organizationId) return;
            }
        }

        throw new ForbiddenException('You cannot access this AI execution');
    }

    private async createTerminalNotification(execution: AiExecution): Promise<void> {
        if (
            !execution.userId
            || execution.userId.startsWith(API_TOKEN_USER_ID_PREFIX)
            || !TERMINAL_NOTIFICATION_STATUSES.includes(execution.status)
        ) return;

        const claimedAt = new Date();
        const leaseExpiredAt = new Date(claimedAt.getTime() - NOTIFICATION_LEASE_MS);
        const claimed = await this.prisma.aiExecution.updateMany({
            where: {
                id: execution.id,
                attempts: { gt: 0 },
                notificationSentAt: null,
                OR: [
                    { notificationClaimedAt: null },
                    { notificationClaimedAt: { lt: leaseExpiredAt } },
                ],
            },
            data: { notificationClaimedAt: claimedAt },
        });
        if (claimed.count !== 1) return;

        const succeeded = execution.status === AiExecutionStatus.SUCCESS;
        const title = succeeded ? 'AI 분석이 완료되었습니다' : 'AI 분석에 실패했습니다';
        const message = succeeded
            ? `${execution.actionLabel || execution.action} 결과를 확인하세요.`
            : execution.error || `${execution.actionLabel || execution.action} 작업을 완료하지 못했습니다.`;

        try {
            await this.notifications.createUserNotification(
                execution.userId,
                'ai_execution',
                title,
                message,
                `/dashboard/ai-results/${execution.id}`,
                `ai-execution:${execution.id}:${execution.status}`,
            );
            await this.prisma.aiExecution.updateMany({
                where: {
                    id: execution.id,
                    notificationSentAt: null,
                    notificationClaimedAt: claimedAt,
                },
                data: {
                    notificationClaimedAt: null,
                    notificationSentAt: new Date(),
                },
            });
        } catch (error) {
            await this.prisma.aiExecution.updateMany({
                where: {
                    id: execution.id,
                    notificationSentAt: null,
                    notificationClaimedAt: claimedAt,
                },
                data: { notificationClaimedAt: null },
            });
            this.logger.warn(`Failed to create AI job notification: ${(error as Error).message}`);
        }
    }
}
