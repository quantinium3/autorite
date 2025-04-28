import { ResultAsync, errAsync } from "neverthrow";
import { config } from "../config/config";

export const sendEmail = (token: string, email: string): ResultAsync<boolean, Error> => {
    const verifyLink = `${config.server.url}/api/v1/verifyEmail/${token}`;
    if (token === "" || email === "") {
        return errAsync(new Error("Email or token is empty"));
    }

    return ResultAsync.fromPromise(
        Promise.resolve(true),
        (error) => new Error("Failed to send email" + error),
    );
};
