export interface AiExecutionAccessActor {
    id: string;
    organizationId?: string;
    roles: string[];
    isApiToken: boolean;
}

export interface AiExecutionAccessSubject {
    userId: string | null;
    organizationId: string | null;
}

export type FindExecutionOwnerOrganization = (
    userId: string,
) => Promise<{ organizationId: string | null } | null>;

export const API_TOKEN_USER_ID_PREFIX = 'api-token:';

export function isApiTokenExecutionOwner(userId: string | null): boolean {
    return userId?.startsWith(API_TOKEN_USER_ID_PREFIX) === true;
}

export async function canAccessAiExecution(
    execution: AiExecutionAccessSubject,
    actor: AiExecutionAccessActor,
    findOwnerOrganization: FindExecutionOwnerOrganization,
): Promise<boolean> {
    if (execution.userId === actor.id) return true;
    if (actor.isApiToken) return false;
    if (actor.roles.includes('SYSTEM_ADMIN')) return true;

    if (!actor.roles.includes('ORG_ADMIN') || !actor.organizationId) return false;
    if (execution.organizationId) {
        return execution.organizationId === actor.organizationId;
    }
    if (!execution.userId || isApiTokenExecutionOwner(execution.userId)) return false;

    const owner = await findOwnerOrganization(execution.userId);
    return owner?.organizationId === actor.organizationId;
}
