import { Router } from "express";
import { handleSignup } from "../controller/auth.controller";

const authRouter = Router();
authRouter.post('/signup', handleSignup)
