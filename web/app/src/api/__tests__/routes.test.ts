import { describe, it, expect } from "vitest";
import routeFixture from "./routes_fixture.json"; // emitted from web.server app.routes

// the URL templates the client constructs (path shape only — params are placeholders)
const CLIENT_TEMPLATES = [
  "/api/scenarios",
  "/api/inputs/{domain_id}",
  "/api/constraints/{domain_id}",
  "/api/certify/{domain_id}",
  "/api/timeline/{domain_id}",
  "/api/certificates/{domain_id}",
  "/api/verify",
].sort();

describe("client URL templates match the registered FastAPI routes (A-8)", () => {
  it("the client surface equals the backend route table", () => {
    expect([...(routeFixture as string[])].sort()).toEqual(CLIENT_TEMPLATES);
  });
});
