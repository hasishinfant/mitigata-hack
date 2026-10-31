import { afterAll } from "vitest";
import { closeRegPool } from "./helpers/db.ts";

afterAll(closeRegPool);
