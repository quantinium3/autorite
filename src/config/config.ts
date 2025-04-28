import { z } from "zod";

const envSchema = z.object({
    NODE_ENV: z.enum(['PRODUCTION', 'DEV']),
    PORT: z.string().default("8000"),
    SERVER_URL: z.string(),
    CORS_ORIGIN: z.string().default(""),
    ACCESS_TOKEN_SECRET: z.string().min(8),
    ACCESS_TOKEN_EXPIRE: z.string().default('1hr'),
    REFRESH_TOKEN_SECRET: z.string().min(8),
    REFRESH_TOKEN_EXPIRE: z.string().default('1d'),
    REFRESH_TOKEN_SECRET_NAME: z.string().min(8),
    DATABASE_URL: z.string(),
    SMTP_HOST: z.string(),
    SMTP_PORT: z.string().default('25'),
    SMTP_USERNAME: z.string(),
    SMTP_PASSWORD: z.string(),
    EMAIL_FROM: z.string().email(),
});

const parsedEnv = envSchema.parse(process.env);

export const config = {
    node_env: parsedEnv.NODE_ENV,
    server: {
        port: parsedEnv.PORT,
        url: parsedEnv.SERVER_URL,
    },
    cors: {
        cors_origin: parsedEnv.CORS_ORIGIN,
    },
    tokens: {
        access_secret: parsedEnv.ACCESS_TOKEN_SECRET,
        access_expire: parsedEnv.ACCESS_TOKEN_EXPIRE,
        refresh_secret: parsedEnv.REFRESH_TOKEN_SECRET,
        refresh_expire: parsedEnv.REFRESH_TOKEN_EXPIRE,
        refresh_secret_name: parsedEnv.REFRESH_TOKEN_SECRET_NAME,
    },
    database_url: parsedEnv.DATABASE_URL,
    smtp: {
        host: parsedEnv.SMTP_HOST,
        port: parsedEnv.SMTP_PORT,
        username: parsedEnv.SMTP_USERNAME,
        password: parsedEnv.SMTP_PASSWORD,
        email_from: parsedEnv.EMAIL_FROM,
    },
};
