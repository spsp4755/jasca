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

const apiTokenUser = {
    id: 'api-token:token-1',
    organizationId: 'org-1',
    role: 'API_TOKEN',
    permissions: ['scans:read'],
    isApiToken: true,
    apiTokenId: 'token-1',
    apiTokenName: 'CI token',
};

const userActor = {
    id: user.id,
    organizationId: user.organizationId,
    roles: ['DEVELOPER'],
    isApiToken: false,
    permissions: [],
    apiTokenId: undefined,
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
            userActor,
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

    it('rejects unauthenticated job requests', async () => {
        const { controller, aiJobService } = createController();

        await expect(controller.createJob({
            action: AiActionType.DASHBOARD_SUMMARY,
            context: {},
        }, {})).rejects.toBeInstanceOf(BadRequestException);
        await expect(controller.getJob('job-1', {})).rejects.toBeInstanceOf(BadRequestException);
        await expect(controller.cancelJob('job-1', {})).rejects.toBeInstanceOf(BadRequestException);
        expect(aiJobService.enqueue).not.toHaveBeenCalled();
    });

    it('preserves the actual API token principal when queueing and polling', async () => {
        const { controller, aiJobService } = createController();
        const expectedActor = {
            id: apiTokenUser.id,
            organizationId: apiTokenUser.organizationId,
            roles: [],
            isApiToken: true,
            permissions: apiTokenUser.permissions,
            apiTokenId: apiTokenUser.apiTokenId,
        };

        await controller.createJob({
            action: AiActionType.DASHBOARD_SUMMARY,
            context: {},
        }, { user: apiTokenUser });
        await controller.getJob('job-1', { user: apiTokenUser });

        expect(aiJobService.enqueue).toHaveBeenCalledWith(
            AiActionType.DASHBOARD_SUMMARY,
            {},
            expectedActor,
        );
        expect(aiJobService.getJob).toHaveBeenCalledWith('job-1', expectedActor);
    });

    it('maps API token admin permission only to ORG_ADMIN-required actions', async () => {
        const { controller, aiJobService } = createController();
        const adminToken = { ...apiTokenUser, permissions: ['admin'] };

        await controller.createJob({
            action: AiActionType.DASHBOARD_RISK_ANALYSIS,
            context: {},
        }, { user: adminToken });
        await expect(controller.createJob({
            action: AiActionType.PERMISSION_RECOMMENDATION,
            context: {},
        }, { user: adminToken })).rejects.toBeInstanceOf(ForbiddenException);

        expect(aiJobService.enqueue).toHaveBeenCalledTimes(1);
    });

    it('keeps ORG_ADMIN and SYSTEM_ADMIN action authorization', async () => {
        const { controller, aiJobService } = createController();
        const orgAdmin = { ...user, roles: [{ role: 'ORG_ADMIN' }] };
        const systemAdmin = { ...user, roles: [{ role: 'SYSTEM_ADMIN' }] };

        await controller.createJob({
            action: AiActionType.DASHBOARD_RISK_ANALYSIS,
            context: {},
        }, { user: orgAdmin });
        await expect(controller.createJob({
            action: AiActionType.PERMISSION_RECOMMENDATION,
            context: {},
        }, { user: orgAdmin })).rejects.toBeInstanceOf(ForbiddenException);
        await controller.createJob({
            action: AiActionType.PERMISSION_RECOMMENDATION,
            context: {},
        }, { user: systemAdmin });

        expect(aiJobService.enqueue).toHaveBeenCalledTimes(2);
    });

    it('delegates ownership enforcement for job reads with the mapped actor', async () => {
        const { controller, aiJobService } = createController();

        const result = await controller.getJob('job-1', { user });

        expect(aiJobService.getJob).toHaveBeenCalledWith('job-1', {
            ...userActor,
        });
        expect(result).toEqual({ id: 'job-1', status: 'RUNNING' });
    });

    it('delegates active-job cancellation with the same mapped actor', async () => {
        const { controller, aiJobService } = createController();

        const result = await controller.cancelJob('job-1', { user });

        expect(aiJobService.cancel).toHaveBeenCalledWith('job-1', {
            ...userActor,
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

    it('preserves synchronous execute for API tokens on generally allowed actions', async () => {
        const { controller, aiService, aiJobService } = createController();

        await controller.executeAi({
            action: AiActionType.DASHBOARD_SUMMARY,
            context: {},
        }, { user: apiTokenUser });

        expect(aiService.executeAction).toHaveBeenCalledWith(
            AiActionType.DASHBOARD_SUMMARY,
            {},
            apiTokenUser.id,
        );
        expect(aiJobService.enqueue).not.toHaveBeenCalled();
    });
});
