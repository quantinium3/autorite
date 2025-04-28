import { status } from 'http-status';
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
import { verify } from 'jsonwebtoken';
import { logger } from '../middleware/logger.ts';

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
        return res.status(status.BAD_REQUEST).json({
            error: parsedBody.error,
        })
    }

    const { username, email, password } = parsedBody.data

    if (!username || !email || !password) {
        return res.status(status.BAD_REQUEST).json({
            message: "Username, Email and Password are required",
        })
    }

    try {
        const [existingUserByEmail] = await db.select().from(userTable).where(eq(userTable.email, email)).limit(1)
        if (existingUserByEmail) {
            return res.status(status.CONFLICT).json({
                message: "User with the same email already exists",
            })
        }

        const [existingUserByUsername] = await db.select().from(userTable).where(eq(userTable.username, username)).limit(1)
        if (existingUserByUsername) {
            return res.status(status.CONFLICT).json({
                message: "User with the same username already exists",
            })
        }

        const hashedPassword = await hash(password, SALT_ROUNDS)
        const userId = createId()
        const emailToken = createId()

        await db.insert(userTable).values({
            id: userId,
            username,
            email,
            password: hashedPassword,
        })

        await db.insert(emailVerificationTable).values({
            id: createId(),
            email,
            token: emailToken,
            expiresAt: new Date(Date.now() + HOUR),
        })

        const emailResult = await sendEmail(emailToken, email)

        emailResult.match(
            (sent: boolean) => {
                console.log(`Successfully sent verification email: ${sent}`)
            },
            (error: Error) => {
                logger.error(`Failed to send verification email: ${error.message}`)
            }
        )

        return res.status(status.OK).json({
            message: "New user created successfully. Please check your email to verify your account.",
        })

    } catch (err) {
        logger.error(err)
        return res.status(status.INTERNAL_SERVER_ERROR).json({
            message: `Failed to create user`,
        })
    }
}

export const handleSignIn = async (req: Request, res: Response) => {
    const cookies = req.cookies
    const parsedBody = userSignInSchema.safeParse(req.body)

    if (!parsedBody.success) {
        return res.status(status.BAD_REQUEST).json({
            message: `Invalid email or password: ${parsedBody.error}`,
        })
    }

    const { email, password } = parsedBody.data

    try {
        const existingUsers = await db.select().from(userTable).where(eq(userTable.email, email))
        const existingUser = existingUsers[0]

        if (!existingUser) {
            return res.status(status.UNAUTHORIZED).json({
                message: "User doesn't exist",
            })
        }

        const passwordIsValid = await compare(password, existingUser.password)
        if (!passwordIsValid) {
            return res.status(status.UNAUTHORIZED).json({
                message: "Password is invalid",
            })
        }

        if (cookies?.[config.tokens.refresh_secret_name]) {
            const oldRefreshToken = cookies[config.tokens.refresh_secret_name]

            const existingSession = await db
                .select()
                .from(sessionTable)
                .where(eq(sessionTable.refreshToken, oldRefreshToken))

            if (existingSession.length === 0 || existingSession[0].userId !== existingUser.id) {
                await db.delete(sessionTable).where(eq(sessionTable.userId, existingUser.id))
            } else {
                await db.delete(sessionTable).where(eq(sessionTable.refreshToken, oldRefreshToken))
            }

            res.clearCookie(config.tokens.refresh_secret_name, {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                path: '/',
            })
        }

        const accessToken = createAccessToken(existingUser.id)
        const newRefreshToken = createRefreshToken(existingUser.id)

        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000) // 1 day expiry

        await db.insert(sessionTable).values({
            id: createId(),
            refreshToken: newRefreshToken,
            userId: existingUser.id,
            expiresAt,
        }).onConflictDoUpdate({
            target: sessionTable.userId,
            set: {
                refreshToken: newRefreshToken,
                expiresAt,
            },
        })

        res.cookie(config.tokens.refresh_secret_name, newRefreshToken, {
            httpOnly: true,
            sameSite: 'none',
            secure: true,
            maxAge: 24 * 60 * 60 * 1000, // 1 day
            path: '/',
        })

        return res.status(status.OK).json({
            accessToken,
        })

    } catch (error) {
        logger.error(error)

        return res.status(status.INTERNAL_SERVER_ERROR).json({
            message: "Failed to login user",
        })
    }
}

export const handleSignOut = async (req: Request, res: Response) => {
    const cookies = req.cookies;
    if (!cookies[config.tokens.refresh_secret_name]) {
        return res.status(status.NO_CONTENT).json({
            message: "user is already signed out."
        })
    }

    const refreshToken = cookies[config.tokens.refresh_secret_name]

    const session = await db.select().from(sessionTable).where(eq(sessionTable.refreshToken, refreshToken));
    if (session.length === 0) {
        res.clearCookie(config.tokens.refresh_secret_name, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            path: '/'
        })
        res.status(status.NO_CONTENT).json({
            message: "user is signed out."
        })
    }

    await db.delete(sessionTable).where(eq(sessionTable.refreshToken, refreshToken))

    res.clearCookie(config.tokens.refresh_secret_name, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        path: '/'
    })

    return res.status(status.NO_CONTENT).json({
        message: "User is signed out"
    });
}

export const handleRefresh = async (req: Request, res: Response) => {
    const refreshToken: string | undefined = req.cookies[config.tokens.refresh_secret_name]

    if (!refreshToken) {
        return res.status(status.UNAUTHORIZED).json({
            message: "Unauthorized request. No refresh token found",
        })
    }

    res.clearCookie(config.tokens.refresh_secret_name, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        path: '/',
    })

    const foundSessions = await db.select().from(sessionTable)
        .where(eq(sessionTable.refreshToken, refreshToken))

    const foundSession = foundSessions[0]

    verify(refreshToken, config.tokens.refresh_secret, async (err, payload: any) => {
        if (err) {
            return res.status(status.FORBIDDEN).json({
                message: "Invalid refresh token",
            })
        }

        const userId = payload.userId

        if (!foundSession) {
            logger.warn('Attempted refresh token reuse!')

            await db.delete(sessionTable).where(eq(sessionTable.userId, userId))

            return res.status(status.FORBIDDEN).json({
                message: "Unauthorized access. Token reuse detected.",
            })
        }

        if (foundSession.userId !== userId) {
            return res.status(status.FORBIDDEN).json({
                message: "Refresh token userId doesn't match.",
            })
        }

        await db.delete(sessionTable).where(eq(sessionTable.refreshToken, refreshToken))

        const accessToken = createAccessToken(userId)
        const newRefreshToken = createRefreshToken(userId)

        await db.insert(sessionTable).values({
            id: createId(),
            refreshToken: newRefreshToken,
            userId,
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        }).catch((err: Error) => {
            logger.error(err)
        })

        res.cookie(config.tokens.refresh_secret_name, newRefreshToken, {
            httpOnly: true,
            sameSite: 'none',
            secure: true,
            maxAge: 24 * 60 * 60 * 1000,
            path: '/',
        })

        return res.status(status.OK).json({
            accessToken,
        })
    })
}

export const handleForgotPassword = async (req: Request, res: Response) => {
    const { email } = req.body;

    if (!email) {
        return res.status(status.BAD_REQUEST).json({
            message: "Email is required",
        })
    }

    const user = await db.select().from(userTable).where(eq(userTable.email, email));
    if (user.length === 0) {
        return res.status(status.NOT_FOUND).json({
            message: "User not found",
        })
    }

    if (!user[0].isVerified) {
        return res.status(status.UNAUTHORIZED).json({
            message: "Unauthorized access. Verify your email"
        })
    }

    const resetToken = createId();
    const expiresAt = new Date(Date.now() + HOUR)

    await db.insert(emailVerificationTable).values({ token: resetToken, expiresAt, email })

    sendResetEmail(email, resetToken);

    return res.status(status.OK).json({
        message: "Password reset email sent"
    })
}

export const handleResetPassword = async (req: Request, res: Response) => {
    const { token } = req.params;
    const { newPassword } = req.body;

    if (!token) {
        res.status(status.BAD_REQUEST).json({
            message: "token is required",
        })
    }

    if (!newPassword) {
        res.status(status.BAD_REQUEST).json({
            message: "Password is required"
        })
    }

    const resetToken = await db.select().from(emailVerificationTable).where(eq(emailVerificationTable.token, token))
    const isTokenValid = new Date() < resetToken[0].expiresAt;
    if (!isTokenValid) {
        return res.status(status.UNAUTHORIZED).json({
            message: "Unauthorized request. invalid or expired token"
        })
    }

    const hashedPassword = await hash(newPassword, 12)
    await db.update(userTable).set({ password: hashedPassword }).where(eq(userTable.id, sessionTable.userId)).returning()

    await db.delete(emailVerificationTable).where(eq(emailVerificationTable.id, sessionTable.userId))
    await db.delete(sessionTable).where(eq(sessionTable.userId, resetToken[0].id))
    return res.status(status.OK).json({
        message: "Password reset successfully"
    })
}
