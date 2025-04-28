import { pgTable, text, timestamp, varchar } from "drizzle-orm/pg-core";
import { userTable } from "./user";
import { InferSelectModel } from "drizzle-orm";

export const emailVerificationTable = pgTable("email_verification", {
    id: text("id").primaryKey(),
    token: text("token").notNull(),
    email: varchar("email", { length: 255 }).notNull().references(() => userTable.email, {onDelete: "cascade"}),
    expiresAt: timestamp("expires_at", {
        withTimezone: true,
        mode: "date",
    }).notNull()
})

export type emailVerification = InferSelectModel<typeof emailVerificationTable>
