import { integer, pgTable, varchar } from "drizzle-orm/pg-core";
import { createId } from "@paralleldrive/cuid2";

export const usersTable = pgTable("users", {
    userId: varchar('user_id', { length: 255 }).primaryKey().default(createId),
    name: varchar({ length: 255 }).notNull(),
    age: integer().notNull(),
    email: varchar({ length: 255 }).notNull().unique(),
});

