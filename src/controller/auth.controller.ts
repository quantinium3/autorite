import httpStatus from 'http-status';
import z from "zod";
import { db } from '../db';
import { sessionTable, userTable } from '../db/schema/user';
import { eq } from 'drizzle-orm';
import { createId } from '@paralleldrive/cuid2';
import { sendEmail } from '../utils/email.utils.ts';
import { compare, hash } from 'bcrypt';
import { emailVerificationTable } from '../db/schema/email.ts';
import { config } from '../config/config.ts';
import { createAccessToken, createRefreshToken } from '../utils/auth.utils.ts';
import { type Request, type Response } from "express";

const userSignUpSchema = z.object({
    username: z.string().min(3),
    email: z.string().email().min(3),
    password: z.string().min(5),
})

const userSignInSchema = z.object({
    email: z.string().email().min(3),
    password: z.string().min(5),
})

const SALT_ROUNDS = 12;
const HOUR = 60 * 60 * 1000;

export const handleSignup = async (req: Request, res: Response) => {
    const parsedBody = userSignUpSchema.safeParse(req.body)
    if (!parsedBody.success) {
        return res.status(httpStatus.BAD_REQUEST).json({
            error: parsedBody.error
        })
    }

    const user = parsedBody.data

    if (!user.username || !user.email || !user.password) {
        return res.status(httpStatus.BAD_REQUEST).json({
            message: "Username, Email and password are required"
        })
    }

    const existingUserByEmail = await db.select().from(userTable).where(eq(userTable.email, user.email)).limit(1);
    if (existingUserByEmail) {
        return res.status(httpStatus.CONFLICT).json({
            message: "User with the same email already exists",
        })
    }

    const existingUserByUsername = await db.select().from(userTable).where(eq(userTable.username, user.username)).limit(1);
    if (existingUserByUsername) {
        return res.status(httpStatus.CONFLICT).json({
            message: "User with the same username exists",
        })
    }

    const hashedPasswd = await hash(user.password, SALT_ROUNDS)
    const token = createId();

    try {
        await db.insert(userTable).values({
            id: createId(),
            username: user.username,
            email: user.email,
            password: hashedPasswd,
        });

        await db.insert(emailVerificationTable).values({
            id: createId(),
            email: user.email,
            token: token,
            expiresAt: new Date(Date.now() + HOUR)
        })

        sendEmail(token, user.email).match(
            (sent: boolean) => {
                console.log(`successfully sent the email: ${sent}`)
            },
            (error: Error) => {
                return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
                    message: `Failed to send verification Email: ${error.message}`
                })
            }
        )

        res.status(httpStatus.OK).json({
            message: "New User created successfully"
        })
    } catch (err) {
        return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
            message: `Failed to create user: ${err}`
        })
    }
}

export const loginUser = async (req: Request, res: Response) => {
    const cookies = req.cookies;
    const parsedBody = userSignInSchema.safeParse(req.body);
    if (!parsedBody.success) {
        return res.status(httpStatus.BAD_REQUEST).json({
            message: `Invalid email or password: ${parsedBody.error}`,
        });
    }

    const user = parsedBody.data;

    try {
        const existingUserByEmail = await db
            .selectDistinct()
            .from(userTable)
            .where(eq(userTable.email, user.email));

        if (!existingUserByEmail || existingUserByEmail.length === 0) {
            return res.status(httpStatus.UNAUTHORIZED).json({
                message: "User doesn't exist"
            });
        }

        const passwdIsValid = await compare(user.password, existingUserByEmail[0].password);
        if (!passwdIsValid) {
            return res.status(httpStatus.UNAUTHORIZED).json({
                message: "Password is invalid"
            });
        }

        if (cookies?.[config.tokens.refresh_secret_name]) {
            const refreshToken = cookies[config.tokens.refresh_secret_name];
            const existingToken = await db
                .selectDistinct()
                .from(sessionTable)
                .where(eq(sessionTable.refreshToken, refreshToken));

            if (!existingToken || existingToken.length === 0 || existingToken[0].userId !== existingUserByEmail[0].id) {
                await db.delete(sessionTable)
                    .where(eq(sessionTable.userId, existingUserByEmail[0].id));
            } else {
                await db.delete(sessionTable)
                    .where(eq(sessionTable.refreshToken, refreshToken));
            }

            res.clearCookie(config.tokens.refresh_secret_name, {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                path: '/'
            });
        }

        const accessToken = createAccessToken(existingUserByEmail[0].id);
        const newRefreshToken = createRefreshToken(existingUserByEmail[0].id);

        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 24);

        await db.insert(sessionTable).values({
            id: createId(),
            refreshToken: newRefreshToken,
            userId: existingUserByEmail[0].id,
            expiresAt: expiresAt
        }).onConflictDoUpdate({
            target: sessionTable.userId,
            set: {
                refreshToken: newRefreshToken,
                expiresAt: expiresAt
            }
        });

        res.cookie(
            config.tokens.refresh_secret_name, newRefreshToken, {
            httpOnly: true,
            sameSite: 'none',
            secure: true,
            maxAge: 24 * 60 * 60 * 1000
        });

        return res.status(200).json({
            accessToken: accessToken,
        });
    } catch (err) {
        return res.status(httpStatus.INTERNAL_SERVER_ERROR).json({
            message: `Failed to login user: ${err}`
        });
    }
}
