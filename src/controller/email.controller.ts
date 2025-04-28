import { Request, Response } from "express";
import { db } from '../db';
import status from "http-status";
import { userTable } from "../db/schema/user";
import { emailVerificationTable } from "../db/schema/email";
import { eq } from "drizzle-orm";
import { createId } from "@paralleldrive/cuid2";
import { sendEmail } from "../utils/email.utils";

const HOUR = 60 * 60 * 1000;

export const sendVerificationEmail = async (req: Request, res: Response) => {
    const { email } = req.body;

    if (!email) {
        return res.status(status.BAD_REQUEST).json({
            message: "Email is required",
        });
    }

    const user = await db.query.userTable.findFirst({
        where: eq(userTable.email, email),
    });

    if (!user) {
        return res.status(status.NOT_FOUND).json({
            message: "User not found",
        });
    }

    if (user.isVerified) {
        return res.status(status.BAD_REQUEST).json({
            message: "User is already verified",
        });
    }

    const existingToken = await db.query.emailVerificationTable.findFirst({
        where: eq(emailVerificationTable.email, email),
    });

    if (existingToken && new Date() < existingToken.expiresAt) {
        return res.status(status.BAD_REQUEST).json({
            message: "Verification email already sent",
        });
    }

    const token = createId();
    const expiresAt = new Date(Date.now() + HOUR);

    await db.insert(emailVerificationTable).values({
        id: createId(),
        token,
        expiresAt,
        email,
    });

    await sendEmail(token, email);

    return res.status(status.OK).json({
        message: "Verification email sent",
    });
};

export const handleVerifyEmail = async (req: Request, res: Response) => {
    const { token } = req.params;

    if (!token) {
        return res.status(status.BAD_REQUEST).json({
            message: "Token is required",
        });
    }

    const verToken = await db.query.emailVerificationTable.findFirst({
        where: eq(emailVerificationTable.token, token),
    });

    if (!verToken || verToken.expiresAt < new Date()) {
        return res.status(status.UNAUTHORIZED).json({
            message: "Invalid or expired token",
        });
    }

    await db.update(userTable)
        .set({ isVerified: true })
        .where(eq(userTable.email, verToken.email));

    await db.delete(emailVerificationTable)
        .where(eq(emailVerificationTable.token, verToken.token));

    return res.status(status.OK).json({
        message: "Email verified successfully",
    });
};
