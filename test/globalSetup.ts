import pg from "pg";
import { migrate, passwordFromUrl } from "../src/store/migrate.ts";
import { hasDb, TEST_DB, testUrl } from "./helpers/db.ts";

export default async function setup(): Promise<void> {
  if (!hasDb) return;
  const admin = new pg.Client({ connectionString: testUrl("DATABASE_URL_ADMIN", "postgres") });
  await admin.connect();
  await admin.query(`drop database if exists ${TEST_DB} with (force)`);
  await admin.query(`create database ${TEST_DB}`);
  await admin.end();
  await migrate(testUrl("DATABASE_URL_ADMIN"), {
    app: passwordFromUrl(process.env.DATABASE_URL_APP),
    broker: passwordFromUrl(process.env.DATABASE_URL_BROKER),
  }, undefined, testUrl("DATABASE_URL_APP"));
}
