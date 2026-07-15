import { ForbiddenException } from '@nestjs/common';
import { AiJobService } from './ai-job.service';

const queuedJob = {
    id: 'execution-1',
    userId: 'user-1',
    action: 'dashboard.summary',
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
    notificationSentAt: null,
    createdAt: new Date('2026-07-15T04:00:00.000Z'),
    updatedAt: new Date('2026-07-15T04:00:00.000Z'),
};

function createService() {
    const prisma = {
        aiExecution: {
            create: jest.fn().mockResolvedValue(queuedJob),
            findFirst: jest.fn(),
            findUnique: jest.fn(),
            updateMany: jest.fn(),
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

    return {
        prisma,
        notifications,
        executor,
        service: new AiJobService(prisma, notifications, executor),
    };
}

describe('AiJobService', () => {
    it('enqueues an AI execution in QUEUED state', async () => {
        const { service, prisma } = createService();
        const action = 'dashboard.summary';
        const context = { projectId: 'project-1' };

        await service.enqueue(action, context, 'user-1');

        expect(prisma.aiExecution.create).toHaveBeenCalledWith({
            data: expect.objectContaining({ status: 'QUEUED', action, context, userId: 'user-1' }),
        });
    });

    it('allows only one worker to claim the oldest queued job', async () => {
        const { service, prisma, executor } = createService();
        prisma.aiExecution.findFirst.mockResolvedValue({ id: queuedJob.id });
        prisma.aiExecution.findUnique.mockResolvedValue({
            ...queuedJob,
            status: 'SUCCESS',
            completedAt: new Date('2026-07-15T04:01:00.000Z'),
        });
        let claimed = false;
        prisma.aiExecution.updateMany.mockImplementation(({ data }: { data: { status?: string } }) => {
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

    it('returns stale RUNNING jobs to QUEUED on module init and starts an unrefed worker', async () => {
        const { service, prisma } = createService();
        prisma.aiExecution.updateMany.mockResolvedValue({ count: 2 });
        const timer = { unref: jest.fn() } as unknown as NodeJS.Timeout;
        const setIntervalSpy = jest.spyOn(global, 'setInterval').mockReturnValue(timer);
        const clearIntervalSpy = jest.spyOn(global, 'clearInterval').mockImplementation();

        try {
            await service.onModuleInit();

            expect(prisma.aiExecution.updateMany).toHaveBeenCalledWith({
                where: {
                    status: 'RUNNING',
                    startedAt: { lt: expect.any(Date) },
                },
                data: { status: 'QUEUED', startedAt: null },
            });
            expect(setIntervalSpy).toHaveBeenCalledWith(expect.any(Function), 5000);
            expect(timer.unref).toHaveBeenCalledTimes(1);
        } finally {
            service.onModuleDestroy();
            setIntervalSpy.mockRestore();
            clearIntervalSpy.mockRestore();
        }
    });

    it('does not claim queued work before Task 2 connects an executor', async () => {
        const { prisma, notifications } = createService();
        const service = new AiJobService(prisma, notifications);

        await service.processNextJob();

        expect(prisma.aiExecution.findFirst).not.toHaveBeenCalled();
        expect(prisma.aiExecution.updateMany).not.toHaveBeenCalled();
    });

    it('cancels an owned active job', async () => {
        const { service, prisma } = createService();
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
        const { service, prisma } = createService();
        prisma.aiExecution.findUnique.mockResolvedValue(queuedJob);

        await expect(service.getJob(queuedJob.id, {
            id: 'user-2',
            roles: ['DEVELOPER'],
        })).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('creates one completion notification with the result link after reserving it', async () => {
        const { service, prisma, notifications } = createService();
        prisma.aiExecution.findFirst.mockResolvedValue({ id: queuedJob.id });
        prisma.aiExecution.findUnique.mockResolvedValue({
            ...queuedJob,
            status: 'SUCCESS',
            completedAt: new Date('2026-07-15T04:01:00.000Z'),
        });
        prisma.aiExecution.updateMany
            .mockResolvedValueOnce({ count: 1 })
            .mockResolvedValueOnce({ count: 1 });

        await service.processNextJob();

        expect(prisma.aiExecution.updateMany).toHaveBeenNthCalledWith(2, {
            where: {
                id: queuedJob.id,
                notificationSentAt: null,
                status: { in: ['SUCCESS', 'ERROR', 'TIMEOUT'] },
            },
            data: { notificationSentAt: expect.any(Date) },
        });
        expect(notifications.createUserNotification).toHaveBeenCalledTimes(1);
        expect(notifications.createUserNotification).toHaveBeenCalledWith(
            'user-1',
            'ai_execution',
            'AI 분석이 완료되었습니다',
            expect.any(String),
            `/dashboard/ai-results/${queuedJob.id}`,
        );
    });

    it('does not create a duplicate notification when another worker reserved it', async () => {
        const { service, prisma, notifications } = createService();
        prisma.aiExecution.findFirst.mockResolvedValue({ id: queuedJob.id });
        prisma.aiExecution.findUnique.mockResolvedValue({
            ...queuedJob,
            status: 'SUCCESS',
            completedAt: new Date('2026-07-15T04:01:00.000Z'),
        });
        prisma.aiExecution.updateMany
            .mockResolvedValueOnce({ count: 1 })
            .mockResolvedValueOnce({ count: 0 });

        await service.processNextJob();

        expect(notifications.createUserNotification).not.toHaveBeenCalled();
    });
});
