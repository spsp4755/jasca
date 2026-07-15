import { ExecutionContext } from '@nestjs/common';
import { JwtAuthGuard } from './jwt-auth.guard';
import { RolesGuard } from './roles.guard';

function createContext(request: Record<string, any>): ExecutionContext {
    return {
        switchToHttp: () => ({
            getRequest: () => request,
        }),
        getHandler: () => function handler() {},
        getClass: () => class TestController {},
    } as unknown as ExecutionContext;
}

describe('API token authentication and role mapping', () => {
    it('creates the real API token principal and maps admin only to ORG_ADMIN', async () => {
        const apiTokenService = {
            validateToken: jest.fn().mockResolvedValue({
                id: 'token-1',
                organizationId: 'org-1',
                permissions: ['admin'],
                name: 'Automation token',
            }),
        };
        const moduleRef = {
            get: jest.fn().mockReturnValue(apiTokenService),
        };
        const request = {
            headers: { authorization: 'Bearer jasca_secret-token' },
        } as Record<string, any>;
        const context = createContext(request);
        const jwtGuard = new JwtAuthGuard(moduleRef as any);

        await expect(jwtGuard.canActivate(context)).resolves.toBe(true);

        expect(apiTokenService.validateToken).toHaveBeenCalledWith('jasca_secret-token');
        expect(request.user).toEqual({
            id: 'api-token:token-1',
            organizationId: 'org-1',
            role: 'API_TOKEN',
            permissions: ['admin'],
            isApiToken: true,
            apiTokenId: 'token-1',
            apiTokenName: 'Automation token',
        });

        let requiredRoles = ['ORG_ADMIN'];
        const reflector = {
            getAllAndOverride: jest.fn().mockImplementation(() => requiredRoles),
        };
        const rolesGuard = new RolesGuard(reflector as any);

        expect(rolesGuard.canActivate(context)).toBe(true);
        requiredRoles = ['SYSTEM_ADMIN'];
        expect(rolesGuard.canActivate(context)).toBe(false);
    });
});
