import { BadRequestException, ForbiddenException, HttpStatus, RequestMethod } from '@nestjs/common';
import { HTTP_CODE_METADATA, METHOD_METADATA, PATH_METADATA } from '@nestjs/common/constants';
import { AiActionType } from './ai-actions';
import { AiController } from './ai.controller';

const user = {
    id: 'user-1',
    email: 'user@example.test',
    name: 'Test User',
    organizationId: 'org-1',
    roles: [{ role: 'DEVELOPER' }],
};

function createController() {
    const aiService = {
        executeAction: jest.fn().mockResolvedValue({
            id: 'sync-execution-1',
            content: 'result',
            summary: 'summary',
            model: 'test-model',
            inputTokens: 10,
            outputTokens: 5,
            usedPrompt: 'prompt',
            isMock: false,
            isSaved: true,
        }),
    };
    const aiExportService = { exportExecution: jest.fn() };
    const aiJobService = {
        enqueue: jest.fn().mockResolvedValue({ id: 'job-1', status: 'QUEUED' }),
        getJob: jest.fn().mockResolvedValue({ id: 'job-1', status: 'RUNNING' }),
        cancel: jest.fn().mockResolvedValue({ id: 'job-1', status: 'CANCELLED' }),
    };
    const controller = new (AiController as any)(aiService, aiExportService, aiJobService);

    return { controller, aiService, aiExportService, aiJobService };
}

describe('AiController job API', () => {
    it('exposes POST, GET, and DELETE job routes', () => {
        const prototype = AiController.prototype as any;

        expect(Reflect.getMetadata(PATH_METADATA, prototype.createJob)).toBe('jobs');
        expect(Reflect.getMetadata(METHOD_METADATA, prototype.createJob)).toBe(RequestMethod.POST);
        expect(Reflect.getMetadata(HTTP_CODE_METADATA, prototype.createJob)).toBe(HttpStatus.ACCEPTED);
        expect(Reflect.getMetadata(PATH_METADATA, prototype.getJob)).toBe('jobs/:id');
        expect(Reflect.getMetadata(METHOD_METADATA, prototype.getJob)).toBe(RequestMethod.GET);
        expect(Reflect.getMetadata(PATH_METADATA, prototype.cancelJob)).toBe('jobs/:id');
        expect(Reflect.getMetadata(METHOD_METADATA, prototype.cancelJob)).toBe(RequestMethod.DELETE);
    });

    it('queues a valid action and returns accepted job metadata', async () => {
        const { controller, aiJobService } = createController();
        const context = { projectId: 'project-1' };

        const result = await controller.createJob({
            action: AiActionType.DASHBOARD_SUMMARY,
            context,
        }, { user });

        expect(aiJobService.enqueue).toHaveBeenCalledWith(
            AiActionType.DASHBOARD_SUMMARY,
            context,
            user.id,
        );
        expect(result).toEqual({ id: 'job-1', status: 'QUEUED' });
    });

    it.each([
        [undefined],
        [{ action: 'unknown.action', context: {} }],
        [{ action: AiActionType.DASHBOARD_SUMMARY, context: null }],
        [{ action: AiActionType.DASHBOARD_SUMMARY, context: [] }],
    ])('rejects an invalid job request', async (dto) => {
        const { controller, aiJobService } = createController();

        await expect(controller.createJob(dto, { user })).rejects.toBeInstanceOf(BadRequestException);
        expect(aiJobService.enqueue).not.toHaveBeenCalled();
    });

    it('applies action role requirements before queueing', async () => {
        const { controller, aiJobService } = createController();

        await expect(controller.createJob({
            action: AiActionType.PERMISSION_RECOMMENDATION,
            context: {},
        }, { user })).rejects.toBeInstanceOf(ForbiddenException);
        expect(aiJobService.enqueue).not.toHaveBeenCalled();
    });

    it('delegates ownership enforcement for job reads with the mapped actor', async () => {
        const { controller, aiJobService } = createController();

        const result = await controller.getJob('job-1', { user });

        expect(aiJobService.getJob).toHaveBeenCalledWith('job-1', {
            id: user.id,
            organizationId: user.organizationId,
            roles: ['DEVELOPER'],
        });
        expect(result).toEqual({ id: 'job-1', status: 'RUNNING' });
    });

    it('delegates active-job cancellation with the same mapped actor', async () => {
        const { controller, aiJobService } = createController();

        const result = await controller.cancelJob('job-1', { user });

        expect(aiJobService.cancel).toHaveBeenCalledWith('job-1', {
            id: user.id,
            organizationId: user.organizationId,
            roles: ['DEVELOPER'],
        });
        expect(result).toEqual({ id: 'job-1', status: 'CANCELLED' });
    });

    it('preserves the synchronous execute response contract', async () => {
        const { controller, aiService, aiJobService } = createController();

        const result = await controller.executeAi({
            action: AiActionType.DASHBOARD_SUMMARY,
            context: {},
        }, { user });

        expect(aiService.executeAction).toHaveBeenCalledWith(
            AiActionType.DASHBOARD_SUMMARY,
            {},
            user.id,
        );
        expect(aiJobService.enqueue).not.toHaveBeenCalled();
        expect(result).toEqual(expect.objectContaining({
            id: 'sync-execution-1',
            action: AiActionType.DASHBOARD_SUMMARY,
            content: 'result',
        }));
    });
});
