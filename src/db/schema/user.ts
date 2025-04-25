import { varchar } from "drizzle-orm/mysql-core";
import { pgTable } from "drizzle-orm/pg-core";

export const users = pgTable('users', {
    id: varchar().
})
