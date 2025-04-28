import { Router } from "express";
import * as authController from "../controller/auth.controller.ts"

export const authRouter = Router();

authRouter.post('/signup', authController.handleSignup);
authRouter.post('/signin', authController.handleSignIn);
authRouter.post('/signout', authController.handleSignOut);
authRouter.post('/refresh', authController.handleRefresh);
