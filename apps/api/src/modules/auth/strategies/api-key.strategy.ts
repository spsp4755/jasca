import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-custom';
import { Request } from 'express';
import * as crypto from 'crypto';
import { AuthService } from '../auth.service';

@Injectable()
export class ApiKeyStrategy extends PassportStrategy(Strategy, 'api-key') {
    constructor(private readonly authService: AuthService) {
        super();
    }

    async validate(req: Request) {
        const apiKey = req.headers['x-api-key'] as string;

        if (!apiKey) {
            throw new UnauthorizedException('API key is required');
        }

        // Hash the API key to compare with stored hash
        const tokenHash = crypto.createHash('sha256').update(apiKey).digest('hex');
        const apiToken = await this.authService.validateApiKey(tokenHash);

        if (!apiToken) {
            throw new UnauthorizedException('Invalid API key');
        }

        return {
            type: 'api-key',
            organizationId: apiToken.organizationId,
            organization: apiToken.organization,
            permissions: apiToken.permissions,
        };
    }
}
