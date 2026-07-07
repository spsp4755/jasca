import {
    BadRequestException,
    Controller,
    Get,
    Post,
    Put,
    Delete,
    Param,
    Body,
    Query,
    UseGuards,
} from '@nestjs/common';
import { Environment } from '@prisma/client';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiQuery } from '@nestjs/swagger';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { PoliciesService } from './policies.service';
import { PolicyEngineService } from './policy-engine.service';
import { CreatePolicyDto, CreatePolicyRuleDto } from './dto/create-policy.dto';

@ApiTags('Policies')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('policies')
export class PoliciesController {
    constructor(
        private readonly policiesService: PoliciesService,
        private readonly policyEngine: PolicyEngineService,
    ) { }

    @Get()
    @ApiOperation({ summary: 'Get all policies' })
    @ApiQuery({ name: 'organizationId', required: false })
    @ApiQuery({ name: 'projectId', required: false })
    async findAll(
        @Query('organizationId') organizationId?: string,
        @Query('projectId') projectId?: string,
        @CurrentUser() user?: any,
    ) {
        return this.policiesService.findAll(user, organizationId, projectId);
    }

    // Exceptions - must be before :id route to avoid being caught by it
    @Get('exceptions')
    @ApiOperation({ summary: 'Get all exceptions' })
    @ApiQuery({ name: 'status', required: false })
    async findExceptions(@Query('status') status?: string, @CurrentUser() user?: any) {
        return this.policiesService.findExceptions(user, status);
    }

    // CI/CD deployment gate - must be before :id route to avoid being caught by it
    @Get('verdict')
    @ApiOperation({ summary: 'Policy PASS/FAIL verdict for CI/CD gates (latest scan unless scanResultId given)' })
    @ApiQuery({ name: 'projectId', required: true })
    @ApiQuery({ name: 'scanResultId', required: false })
    @ApiQuery({ name: 'environment', required: false, enum: Environment })
    @ApiQuery({ name: 'newOnly', required: false, description: 'Gate only on vulnerabilities new since the previous scan' })
    async verdict(
        @Query('projectId') projectId: string,
        @Query('scanResultId') scanResultId?: string,
        @Query('environment') environment?: Environment,
        @Query('newOnly') newOnly?: string,
        @CurrentUser() user?: any,
    ) {
        if (!projectId) {
            throw new BadRequestException('projectId is required');
        }
        if (environment && !Object.values(Environment).includes(environment)) {
            throw new BadRequestException(`Invalid environment: ${environment}`);
        }
        return this.policyEngine.verdict(projectId, scanResultId, environment, user, newOnly === 'true');
    }

    @Get(':id')
    @ApiOperation({ summary: 'Get policy by ID' })
    async findById(@Param('id') id: string, @CurrentUser() user?: any) {
        return this.policiesService.findById(id, user);
    }


    @Post()
    @Roles('ORG_ADMIN', 'PROJECT_ADMIN', 'SECURITY_ADMIN')
    @ApiOperation({ summary: 'Create a new policy' })
    async create(@Body() dto: CreatePolicyDto, @CurrentUser() user?: any) {
        return this.policiesService.create(dto, user);
    }

    @Put(':id')
    @Roles('ORG_ADMIN', 'PROJECT_ADMIN', 'SECURITY_ADMIN')
    @ApiOperation({ summary: 'Update a policy' })
    async update(@Param('id') id: string, @Body() dto: Partial<CreatePolicyDto>, @CurrentUser() user?: any) {
        return this.policiesService.update(id, dto, user);
    }

    @Delete(':id')
    @Roles('ORG_ADMIN', 'SECURITY_ADMIN')
    @ApiOperation({ summary: 'Delete a policy' })
    async delete(@Param('id') id: string, @CurrentUser() user?: any) {
        return this.policiesService.delete(id, user);
    }

    // Policy Rules
    @Post(':id/rules')
    @Roles('ORG_ADMIN', 'PROJECT_ADMIN', 'SECURITY_ADMIN')
    @ApiOperation({ summary: 'Add rule to policy' })
    async addRule(@Param('id') id: string, @Body() rule: CreatePolicyRuleDto, @CurrentUser() user?: any) {
        return this.policiesService.addRule(id, rule, user);
    }

    @Delete('rules/:ruleId')
    @Roles('ORG_ADMIN', 'PROJECT_ADMIN', 'SECURITY_ADMIN')
    @ApiOperation({ summary: 'Remove rule from policy' })
    async removeRule(@Param('ruleId') ruleId: string, @CurrentUser() user?: any) {
        return this.policiesService.removeRule(ruleId, user);
    }

    // Policy Evaluation
    @Post('evaluate')
    @ApiOperation({ summary: 'Evaluate policies against a scan result' })
    async evaluate(@Body() body: { projectId: string; scanResultId: string }, @CurrentUser() user?: any) {
        return this.policyEngine.evaluate(body.projectId, body.scanResultId, undefined, user);
    }

    @Post(':id/exceptions')

    @ApiOperation({ summary: 'Request an exception' })
    async requestException(
        @Param('id') policyId: string,
        @Body()
        body: {
            exceptionType: string;
            targetValue: string;
            reason: string;
            expiresAt?: string;
        },
        @CurrentUser() user: any,
    ) {
        return this.policiesService.requestException({
            policyId,
            exceptionType: body.exceptionType,
            targetValue: body.targetValue,
            reason: body.reason,
            requestedById: user.id,
            expiresAt: body.expiresAt ? new Date(body.expiresAt) : undefined,
        }, user);
    }

    @Put('exceptions/:id/approve')
    @Roles('ORG_ADMIN', 'PROJECT_ADMIN', 'SECURITY_ADMIN')
    @ApiOperation({ summary: 'Approve an exception' })
    async approveException(@Param('id') id: string, @CurrentUser() user: any) {
        return this.policiesService.approveException(id, user.id, user);
    }

    @Put('exceptions/:id/reject')
    @Roles('ORG_ADMIN', 'PROJECT_ADMIN', 'SECURITY_ADMIN')
    @ApiOperation({ summary: 'Reject an exception' })
    async rejectException(@Param('id') id: string, @CurrentUser() user: any) {
        return this.policiesService.rejectException(id, user.id, user);
    }
}
