import express, { type Request, type Response, type Express } from "express";
import helmet from "helmet";
import { config } from "./config/config";
import cors from "cors";
import { limiter } from "./utils";
import { authRouter } from "./routes/auth.routes";
import cookieParser from "cookie-parser";
import status from "http-status";
import path from "path";
import { logger } from "./middleware/logger";
import { errorHandler } from "./middleware/errorHandler";

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
app.use(cors())

if (config.node_env === "PRODUCTION") {
    app.use("/api/v1/auth", limiter);
}

app.use("/api/v1/auth", authRouter);

app.all("", (req: Request, res: Response) => {
    res.status(status.NOT_FOUND);
    if (req.accepts('html')) {
        res.sendFile(path.join(__dirname, 'views', '404.html'))
    } else if (req.accepts('json')) {
        res.json({ error: "404 Not Found" })
    } else {
        res.type('txt').send('404 Not Found')
    }
});

app.use(errorHandler);

const server = app.listen(Number(config.server.port), () => {
    logger.log('info', `Server is running on PORT: ${config.server.port}`)
})

process.on('SIGTERM', () => {
    logger.info('Closing Server')
    server.close((err) => {
        logger.info('Server closed')
        process.exit(err ? 1 : 0)
    })
})
