import { ForbiddenException, ServiceUnavailableException } from '@nestjs/common';
import { AiActionType } from './ai-actions';
import { AI_JOB_EXECUTOR, AiJobService } from './ai-job.service';
import { AiModule } from './ai.module';
import { AiService } from './ai.service';

const queuedJob = {
    id: 'execution-1',
    userId: 'user-1',
    action: AiActionType.DASHBOARD_SUMMARY,
    actionLabel: null,
    provider: null,
    model: null,
    inputTokens: 0,
    outputTokens: 0,
    durationMs: 0,
    status: 'QUEUED',
    error: null,
    context: { projectId: 'project-1' },
    result: null,
    attempts: 0,
    startedAt: null,
    completedAt: null,
    notificationClaimedAt: null,
    notificationSentAt: null,
    createdAt: new Date('2026-07-15T04:00:00.000Z'),
    updatedAt: new Date('2026-07-15T04:00:00.000Z'),
};

const completedJob = {
    ...queuedJob,
    attempts: 1,
    status: 'SUCCESS',
    completedAt: new Date('2026-07-15T04:01:00.000Z'),
};

function createDependencies() {
    const prisma = {
        aiExecution: {
            create: jest.fn().mockResolvedValue(queuedJob),
            findFirst: jest.fn().mockResolvedValue(null),
            findUnique: jest.fn().mockResolvedValue(null),
            updateMany: jest.fn().mockResolvedValue({ count: 0 }),
        },
        systemSettings: {
            findUnique: jest.fn().mockResolvedValue(null),
        },
        user: {
            findUnique: jest.fn(),
        },
    } as any;
    const notifications = {
        createUserNotification: jest.fn().mockResolvedValue({ id: 'notification-1' }),
    } as any;
    const executor = {
        runQueuedExecution: jest.fn().mockResolvedValue(undefined),
    };

    return { prisma, notifications, executor };
}

function createJobService() {
    const dependencies = createDependencies();
    return {
        ...dependencies,
        service: new AiJobService(
            dependencies.prisma,
            dependencies.notifications,
            dependencies.executor,
        ),
    };
}

function routeWorkerQueries(prisma: any, queued: { id: string } | null, pending: unknown = null) {
    prisma.aiExecution.findFirst.mockImplementation(({ where }: { where: { status: unknown } }) => (
        where.status === 'QUEUED' ? Promise.resolve(queued) : Promise.resolve(pending)
    ));
}

describe('AiJobService', () => {
    it('binds the job executor token to the real AiService', () => {
        const providers = Reflect.getMetadata('providers', AiModule);

        expect(providers).toEqual(expect.arrayContaining([
            { provide: AI_JOB_EXECUTOR, useExisting: AiService },
        ]));
    });

    it('enqueues an AI execution in QUEUED state', async () => {
        const { service, prisma } = createJobService();
        const context = { projectId: 'project-1' };

        await service.enqueue(AiActionType.DASHBOARD_SUMMARY, context, 'user-1');

        expect(prisma.aiExecution.create).toHaveBeenCalledWith({
            data: expect.objectContaining({
                status: 'QUEUED',
                action: AiActionType.DASHBOARD_SUMMARY,
                context,
                userId: 'user-1',
            }),
        });
    });

    it('allows only one worker to claim the oldest queued job', async () => {
        const { service, prisma, executor } = createJobService();
        routeWorkerQueries(prisma, { id: queuedJob.id });
        prisma.aiExecution.findUnique.mockResolvedValue(completedJob);
        let claimed = false;
        prisma.aiExecution.updateMany.mockImplementation(({ data }: { data: Record<string, unknown> }) => {
            if (data.status === 'RUNNING') {
                if (claimed) return Promise.resolve({ count: 0 });
                claimed = true;
            }
            return Promise.resolve({ count: 1 });
        });

        await Promise.all([service.processNextJob(), service.processNextJob()]);

        expect(executor.runQueuedExecution).toHaveBeenCalledTimes(1);
        expect(executor.runQueuedExecution).toHaveBeenCalledWith(queuedJob.id);
    });

    it('recovers stale jobs by heartbeat on startup and every worker cycle', async () => {
        const { service, prisma } = createJobService();
        const timer = { unref: jest.fn() } as unknown as NodeJS.Timeout;
        const setIntervalSpy = jest.spyOn(global, 'setInterval').mockReturnValue(timer);
        const clearIntervalSpy = jest.spyOn(global, 'clearInterval').mockImplementation();

        try {
            await service.onModuleInit();
            await service.processNextJob();

            const recoveryCalls = prisma.aiExecution.updateMany.mock.calls.filter(([query]: any[]) => (
                query.where.status === 'RUNNING' && query.data.status === 'QUEUED'
            ));
            expect(recoveryCalls).toHaveLength(2);
            expect(recoveryCalls[0][0]).toEqual({
                where: {
                    status: 'RUNNING',
                    updatedAt: { lt: expect.any(Date) },
                },
                data: { status: 'QUEUED', startedAt: null },
            });
            expect(timer.unref).toHaveBeenCalledTimes(1);
        } finally {
            service.onModuleDestroy();
            setIntervalSpy.mockRestore();
            clearIntervalSpy.mockRestore();
        }
    });

    it('heartbeats a claimed RUNNING job while execution is in progress', async () => {
        const { service, prisma, executor } = createJobService();
        routeWorkerQueries(prisma, { id: queuedJob.id });
        prisma.aiExecution.findUnique.mockResolvedValue({ ...queuedJob, status: 'CANCELLED' });
        prisma.aiExecution.updateMany.mockImplementation(({ data }: { data: Record<string, unknown> }) => (
            Promise.resolve({ count: data.status === 'RUNNING' ? 1 : 0 })
        ));

        let finishExecution!: () => void;
        executor.runQueuedExecution.mockImplementation(() => new Promise<void>((resolve) => {
            finishExecution = resolve;
        }));
        let heartbeat!: () => void;
        const timer = { unref: jest.fn() } as unknown as NodeJS.Timeout;
        const setIntervalSpy = jest.spyOn(global, 'setInterval').mockImplementation((callback: any) => {
            heartbeat = callback;
            return timer;
        });
        const clearIntervalSpy = jest.spyOn(global, 'clearInterval').mockImplementation();

        try {
            const processing = service.processNextJob();
            for (let i = 0; i < 10 && !executor.runQueuedExecution.mock.calls.length; i += 1) {
                await Promise.resolve();
            }
            expect(executor.runQueuedExecution).toHaveBeenCalledTimes(1);

            heartbeat();
            await Promise.resolve();

            expect(prisma.aiExecution.updateMany).toHaveBeenCalledWith({
                where: { id: queuedJob.id, status: 'RUNNING' },
                data: { updatedAt: expect.any(Date) },
            });

            finishExecution();
            await processing;
        } finally {
            setIntervalSpy.mockRestore();
            clearIntervalSpy.mockRestore();
        }
    });

    it('cancels an owned active job', async () => {
        const { service, prisma } = createJobService();
        prisma.aiExecution.findUnique.mockResolvedValue(queuedJob);
        prisma.aiExecution.updateMany.mockResolvedValue({ count: 1 });

        const cancelled = await service.cancel(queuedJob.id, {
            id: 'user-1',
            roles: ['DEVELOPER'],
        });

        expect(prisma.aiExecution.updateMany).toHaveBeenCalledWith({
            where: { id: queuedJob.id, status: { in: ['QUEUED', 'RUNNING'] } },
            data: { status: 'CANCELLED', completedAt: expect.any(Date) },
        });
        expect(cancelled.status).toBe('CANCELLED');
    });

    it('rejects access to another user\'s job', async () => {
        const { service, prisma } = createJobService();
        prisma.aiExecution.findUnique.mockResolvedValue(queuedJob);

        await expect(service.getJob(queuedJob.id, {
            id: 'user-2',
            roles: ['DEVELOPER'],
        })).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('leases terminal notifications so concurrent workers create only one', async () => {
        const { service, prisma, notifications } = createJobService();
        routeWorkerQueries(prisma, null, completedJob);
        let leased = false;
        prisma.aiExecution.updateMany.mockImplementation(({ data }: { data: Record<string, unknown> }) => {
            if (data.notificationClaimedAt instanceof Date) {
                if (leased) return Promise.resolve({ count: 0 });
                leased = true;
            }
            return Promise.resolve({ count: 1 });
        });

        await Promise.all([service.processNextJob(), service.processNextJob()]);

        expect(notifications.createUserNotification).toHaveBeenCalledTimes(1);
        expect(prisma.aiExecution.findFirst).toHaveBeenCalledWith({
            where: {
                attempts: { gt: 0 },
                status: { in: ['SUCCESS', 'ERROR', 'TIMEOUT'] },
                notificationSentAt: null,
                OR: [
                    { notificationClaimedAt: null },
                    { notificationClaimedAt: { lt: expect.any(Date) } },
                ],
            },
            orderBy: { completedAt: 'asc' },
        });
        expect(prisma.aiExecution.updateMany).toHaveBeenCalledWith({
            where: {
                id: completedJob.id,
                attempts: { gt: 0 },
                notificationSentAt: null,
                OR: [
                    { notificationClaimedAt: null },
                    { notificationClaimedAt: { lt: expect.any(Date) } },
                ],
            },
            data: { notificationClaimedAt: expect.any(Date) },
        });
    });

    it('releases a failed notification lease and retries it on the next cycle', async () => {
        const { service, prisma, notifications } = createJobService();
        routeWorkerQueries(prisma, null, completedJob);
        notifications.createUserNotification
            .mockRejectedValueOnce(new Error('notifications unavailable'))
            .mockResolvedValueOnce({ id: 'notification-1' });
        prisma.aiExecution.updateMany.mockResolvedValue({ count: 1 });

        await service.processNextJob();
        await service.processNextJob();

        expect(notifications.createUserNotification).toHaveBeenCalledTimes(2);
        expect(prisma.aiExecution.updateMany).toHaveBeenCalledWith({
            where: {
                id: completedJob.id,
                notificationSentAt: null,
                notificationClaimedAt: expect.any(Date),
            },
            data: { notificationClaimedAt: null },
        });
        expect(prisma.aiExecution.updateMany).toHaveBeenCalledWith({
            where: {
                id: completedJob.id,
                notificationSentAt: null,
                notificationClaimedAt: expect.any(Date),
            },
            data: {
                notificationClaimedAt: null,
                notificationSentAt: expect.any(Date),
            },
        });
    });
});

describe('AiService queued execution boundary', () => {
    it('keeps synchronous execution on the create path', async () => {
        const { prisma } = createDependencies();
        prisma.aiExecution.create.mockResolvedValue({ ...completedJob, id: 'sync-execution-1' });
        const service = new AiService(prisma);

        const result = await service.executeAction(
            AiActionType.DASHBOARD_SUMMARY,
            queuedJob.context,
            'user-1',
        );

        expect(result.id).toBe('sync-execution-1');
        expect(prisma.aiExecution.create).toHaveBeenCalledTimes(1);
        expect(prisma.aiExecution.updateMany).not.toHaveBeenCalled();
    });

    it('persists queued completion with a RUNNING compare-and-set', async () => {
        const { prisma } = createDependencies();
        prisma.aiExecution.findUnique.mockResolvedValue({ ...queuedJob, status: 'RUNNING' });
        prisma.aiExecution.updateMany.mockResolvedValue({ count: 1 });
        const service = new AiService(prisma);

        await service.runQueuedExecution(queuedJob.id);

        expect(prisma.aiExecution.create).not.toHaveBeenCalled();
        expect(prisma.aiExecution.updateMany).toHaveBeenCalledWith({
            where: { id: queuedJob.id, status: 'RUNNING' },
            data: expect.objectContaining({
                status: 'SUCCESS',
                completedAt: expect.any(Date),
                result: expect.any(String),
            }),
        });
    });

    it('does not overwrite CANCELLED when the completion compare-and-set loses', async () => {
        const { prisma } = createDependencies();
        prisma.aiExecution.findUnique.mockResolvedValue({ ...queuedJob, status: 'RUNNING' });
        prisma.aiExecution.updateMany.mockResolvedValue({ count: 0 });
        const service = new AiService(prisma);

        await service.runQueuedExecution(queuedJob.id);

        expect(prisma.aiExecution.updateMany).toHaveBeenCalledWith(expect.objectContaining({
            where: { id: queuedJob.id, status: 'RUNNING' },
        }));
        expect(prisma.aiExecution.create).not.toHaveBeenCalled();
    });

    it('persists queued provider failure with a RUNNING compare-and-set', async () => {
        const { prisma } = createDependencies();
        prisma.aiExecution.findUnique.mockResolvedValue({ ...queuedJob, status: 'RUNNING' });
        prisma.aiExecution.updateMany.mockResolvedValue({ count: 1 });
        prisma.systemSettings.findUnique.mockImplementation(({ where }: any) => (
            where.key === 'ai'
                ? Promise.resolve({
                    value: {
                        provider: 'openai',
                        apiUrl: 'https://ai.example.test',
                        apiKey: 'test-key',
                        model: 'test-model',
                        enableAutoSummary: true,
                        allowMockFallback: false,
                    },
                })
                : Promise.resolve(null)
        ));
        const fetchSpy = jest.spyOn(global, 'fetch').mockRejectedValue(new Error('provider down'));
        const service = new AiService(prisma);

        try {
            await expect(service.runQueuedExecution(queuedJob.id))
                .rejects.toBeInstanceOf(ServiceUnavailableException);
        } finally {
            fetchSpy.mockRestore();
        }

        expect(prisma.aiExecution.updateMany).toHaveBeenCalledWith({
            where: { id: queuedJob.id, status: 'RUNNING' },
            data: expect.objectContaining({
                status: 'ERROR',
                completedAt: expect.any(Date),
                error: 'provider down',
            }),
        });
        expect(prisma.aiExecution.create).not.toHaveBeenCalled();
    });
});
