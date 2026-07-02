import {
    Controller,
    Get,
    Post,
    Delete,
    Param,
    Body,
    UseGuards,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth, ApiOperation } from '@nestjs/swagger';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { NotificationsService, UserNotification } from './notifications.service';

@ApiTags('Notifications')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('notifications')
export class NotificationsController {
    constructor(private readonly notificationsService: NotificationsService) { }

    @Get()
    @ApiOperation({ summary: 'Get all notifications for current user' })
    async findAll(@CurrentUser() user: { id: string }): Promise<UserNotification[]> {
        return this.notificationsService.getUserNotifications(user.id);
    }

    @Post(':id/read')
    @ApiOperation({ summary: 'Mark notification as read' })
    async markAsRead(
        @Param('id') id: string,
        @CurrentUser() user: { id: string },
    ) {
        return this.notificationsService.markAsRead(id, user.id);
    }

    @Post('read-all')
    @ApiOperation({ summary: 'Mark all notifications as read' })
    async markAllAsRead(@CurrentUser() user: { id: string }) {
        return this.notificationsService.markAllAsRead(user.id);
    }

    @Delete(':id')
    @ApiOperation({ summary: 'Delete notification for current user' })
    async remove(
        @Param('id') id: string,
        @CurrentUser() user: { id: string },
    ) {
        return this.notificationsService.deleteUserNotification(id, user.id);
    }

    @Post('delete-bulk')
    @ApiOperation({ summary: 'Delete selected notifications for current user' })
    async removeBulk(
        @Body() body: { ids?: string[] },
        @CurrentUser() user: { id: string },
    ) {
        return this.notificationsService.deleteUserNotifications(body.ids || [], user.id);
    }

    @Get('unread-count')
    @ApiOperation({ summary: 'Get unread notification count' })
    async getUnreadCount(@CurrentUser() user: { id: string }): Promise<{ count: number }> {
        const count = await this.notificationsService.getUnreadCount(user.id);
        return { count };
    }
}
