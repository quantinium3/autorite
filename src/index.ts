import express, { type Express } from "express";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import { config } from "./config/config";
import cors from "cors";
import { limiter } from "./utils";

const port = process.env.PORT;
if (!port) {
    console.log("PORT environment variable not defined")
    process.exit(1);
}

const app: Express = express();
app.use(helmet.frameguard({ action: 'deny' }));
app.use(express.json({ limit: '1kb' }));
app.use(express.urlencoded({ extended: true, limit: '1kb' }));
app.use(cookieParser())
app.use(cors(config.cors.cors_origin))

if(config.node_env === "PRODUCTION") {
    app.use("/api/v1/auth", limiter);
}

app.use('/api/v1/auth', authRouter);
