import { NotificationsService } from './notifications.service';

const notification = {
    id: 'notification-1',
    userId: 'user-1',
    type: 'ai_execution',
    title: 'AI analysis complete',
    message: 'View the result.',
    link: '/dashboard/ai-results/execution-1',
    deduplicationKey: null,
    isRead: false,
    createdAt: new Date('2026-07-15T04:00:00.000Z'),
};

function createService() {
    const prisma = {
        userNotification: {
            create: jest.fn().mockResolvedValue(notification),
            upsert: jest.fn().mockResolvedValue({
                ...notification,
                deduplicationKey: 'ai-execution:execution-1:SUCCESS',
            }),
        },
    } as any;

    return { prisma, service: new NotificationsService(prisma) };
}

describe('NotificationsService.createUserNotification', () => {
    it('keeps the existing create path when no deduplication key is provided', async () => {
        const { prisma, service } = createService();

        await service.createUserNotification(
            notification.userId,
            notification.type,
            notification.title,
            notification.message,
            notification.link,
        );

        expect(prisma.userNotification.create).toHaveBeenCalledWith({
            data: {
                userId: notification.userId,
                type: notification.type,
                title: notification.title,
                message: notification.message,
                link: notification.link,
                isRead: false,
            },
        });
        expect(prisma.userNotification.upsert).not.toHaveBeenCalled();
    });

    it('atomically reuses a notification with the same deduplication key', async () => {
        const { prisma, service } = createService();
        const deduplicationKey = 'ai-execution:execution-1:SUCCESS';

        const result = await service.createUserNotification(
            notification.userId,
            notification.type,
            notification.title,
            notification.message,
            notification.link,
            deduplicationKey,
        );

        expect(prisma.userNotification.upsert).toHaveBeenCalledWith({
            where: { deduplicationKey },
            update: {},
            create: {
                userId: notification.userId,
                type: notification.type,
                title: notification.title,
                message: notification.message,
                link: notification.link,
                deduplicationKey,
                isRead: false,
            },
        });
        expect(prisma.userNotification.create).not.toHaveBeenCalled();
        expect(result.deduplicationKey).toBe(deduplicationKey);
    });
});
