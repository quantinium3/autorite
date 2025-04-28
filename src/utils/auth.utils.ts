import jwt from 'jsonwebtoken';
import { config } from '../config/config';


export const createAccessToken = (userId: number | string): string => {
    return jwt.sign({ userId: userId }, config.tokens.access_secret, {
        expiresIn: '1hr'
    });
};

export const createRefreshToken = (userId: string): string => {
    return jwt.sign({ userId: userId }, config.tokens.refresh_secret, {
        expiresIn: '1d'
    })
}
