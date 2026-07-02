import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { PasswordPolicyService } from '../auth/services/password-policy.service';

@Module({
    controllers: [UsersController],
    providers: [UsersService, PasswordPolicyService],
    exports: [UsersService],
})
export class UsersModule { }
