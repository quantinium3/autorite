import { Request, Response } from "express";
import { logger } from "./logger";
import status from "http-status";

export const errorHandler = (err: Error, _req: Request, res: Response): void => {
    logger.error(err)
    res.status(status.INTERNAL_SERVER_ERROR).json({
        message: "Error: " + err.message
    })
}
