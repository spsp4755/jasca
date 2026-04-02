import {
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
import { ApiTags, ApiBearerAuth, ApiOperation, ApiQuery } from '@nestjs/swagger';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Permissions } from '../../common/decorators/permissions.decorator';
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
    @Permissions('policy:read')
    @ApiOperation({ summary: 'Get all policies' })
    @ApiQuery({ name: 'organizationId', required: false })
    @ApiQuery({ name: 'projectId', required: false })
    async findAll(
        @Query('organizationId') organizationId?: string,
        @Query('projectId') projectId?: string,
    ) {
        return this.policiesService.findAll(organizationId, projectId);
    }

    // Exceptions - must be before :id route to avoid being caught by it
    @Get('exceptions')
    @Permissions('exception:read')
    @ApiOperation({ summary: 'Get all exceptions' })
    @ApiQuery({ name: 'status', required: false })
    async findExceptions(@Query('status') status?: string) {
        return this.policiesService.findExceptions(status);
    }

    @Get(':id')
    @Permissions('policy:read')
    @ApiOperation({ summary: 'Get policy by ID' })
    async findById(@Param('id') id: string) {
        return this.policiesService.findById(id);
    }


    @Post()
    @Permissions('policy:create')
    @ApiOperation({ summary: 'Create a new policy' })
    async create(@Body() dto: CreatePolicyDto) {
        return this.policiesService.create(dto);
    }

    @Put(':id')
    @Permissions('policy:update')
    @ApiOperation({ summary: 'Update a policy' })
    async update(@Param('id') id: string, @Body() dto: Partial<CreatePolicyDto>) {
        return this.policiesService.update(id, dto);
    }

    @Delete(':id')
    @Permissions('policy:delete')
    @ApiOperation({ summary: 'Delete a policy' })
    async delete(@Param('id') id: string) {
        return this.policiesService.delete(id);
    }

    // Policy Rules
    @Post(':id/rules')
    @Permissions('policy:update')
    @ApiOperation({ summary: 'Add rule to policy' })
    async addRule(@Param('id') id: string, @Body() rule: CreatePolicyRuleDto) {
        return this.policiesService.addRule(id, rule);
    }

    @Delete('rules/:ruleId')
    @Permissions('policy:update')
    @ApiOperation({ summary: 'Remove rule from policy' })
    async removeRule(@Param('ruleId') ruleId: string) {
        return this.policiesService.removeRule(ruleId);
    }

    // Policy Evaluation
    @Post('evaluate')
    @Permissions('policy:read')
    @ApiOperation({ summary: 'Evaluate policies against a scan result' })
    async evaluate(@Body() body: { projectId: string; scanResultId: string }) {
        return this.policyEngine.evaluate(body.projectId, body.scanResultId);
    }

    @Post(':id/exceptions')
    @Permissions('exception:request')
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
        });
    }

    @Put('exceptions/:id/approve')
    @Permissions('exception:approve')
    @ApiOperation({ summary: 'Approve an exception' })
    async approveException(@Param('id') id: string, @CurrentUser() user: any) {
        return this.policiesService.approveException(id, user.id);
    }

    @Put('exceptions/:id/reject')
    @Permissions('exception:approve')
    @ApiOperation({ summary: 'Reject an exception' })
    async rejectException(@Param('id') id: string, @CurrentUser() user: any) {
        return this.policiesService.rejectException(id, user.id);
    }
}
