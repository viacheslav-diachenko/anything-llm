jest.mock("../models/user", () => {
  const store = [];
  return {
    User: {
      findOrCreate: jest.fn(async ({ username }) => {
        let user = store.find((u) => u.username === username);
        const created = !user;
        if (!user) {
          user = { id: store.length + 1, username, role: "default" };
          store.push(user);
        }
        return { user, created };
      }),
      _update: jest.fn(async (id, data) => {
        const user = store.find((u) => u.id === id);
        Object.assign(user, data);
        return { user, message: null };
      }),
      count: jest.fn(async (clause) => store.filter((u) => u.username === clause.username).length),
    },
  };
});

const { userFromSession } = require("../utils/http");
const { User } = require("../models/user");

describe("userFromSession reverse proxy", () => {
  beforeEach(() => {
    process.env.MULTI_USER_MODE = "true";
    process.env.REVERSE_PROXY_AUTH_ENABLED = "true";
    process.env.REVERSE_PROXY_AUTH_ADMIN_GROUPS = "admins";
    process.env.REVERSE_PROXY_AUTH_MANAGER_GROUPS = "managers";
  });

  test("assigns admin role from group", async () => {
    const req = {
      header: (h) => ({
        "Remote-User": "alice",
        "Remote-Groups": "admins",
      }[h]),
    };
    const user = await userFromSession(req);
    expect(user.username).toBe("alice");
    expect(user.role).toBe("admin");
    expect(await User.count({ username: "alice" })).toBe(1);
    const user2 = await userFromSession(req);
    expect(user2.id).toBe(user.id);
    expect(await User.count({ username: "alice" })).toBe(1);
  });

  test("assigns manager role from group", async () => {
    const req = {
      header: (h) => ({
        "Remote-User": "bob",
        "Remote-Groups": "team,managers",
      }[h]),
    };
    const user = await userFromSession(req);
    expect(user.role).toBe("manager");
  });

  test("defaults to normal role", async () => {
    const req = {
      header: (h) => ({
        "Remote-User": "eve",
        "Remote-Groups": "users",
      }[h]),
    };
    const user = await userFromSession(req);
    expect(user.role).toBe("default");
  });
});
