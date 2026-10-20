const http = require("http");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { dbCall, eq } = require("./db");

const SECRET = process.env.JWT_SECRET;


function text(value) {

    return String(value || "").trim();

}


function cleanEmail(value) {

    return text(value).toLowerCase();

}


function send(res, status, data) {

    res.writeHead(status, { "Content-Type": "application/json" });

    res.end(JSON.stringify(data));

}


function readBody(req) {

    return new Promise(function(resolve) {

        let raw = "";

        req.on("data", function(chunk) {

            raw += chunk;

        });

        req.on("end", function() {

            try {

                resolve(JSON.parse(raw) || {});

            } catch (error) {

                resolve({});

            }

        });

    });

}


// The sign-in token is the account id and an end time, signed with the secret
function sign(data) {

    return crypto.createHmac("sha256", SECRET).update(data).digest("base64url");

}


function makeToken(id) {

    let payload = { id: id, expires: Date.now() + 8 * 60 * 60 * 1000 };

    let data = Buffer.from(JSON.stringify(payload)).toString("base64url");

    return data + "." + sign(data);

}


function readToken(token) {

    let parts = token.split(".");

    if (parts.length !== 2 || sign(parts[0]) !== parts[1]) {

        return null;

    }

    try {

        let payload = JSON.parse(Buffer.from(parts[0], "base64url").toString());

        if (payload.expires > Date.now()) {

            return payload.id;

        }

    } catch (error) {

        return null;

    }

    return null;

}


// The password is never included.
function makeUser(row) {

    return {
        id: row.id,
        role: row.role,
        name: row.name,
        email: row.email,
        address: row.address,
        contact: row.contact,
        createdAt: row.created_at
    };

}


function makeRequest(row, resident) {

    return {
        id: row.id,
        requestNo: row.request_no,
        documentType: row.document_type,
        purpose: row.purpose,
        releaseMethod: row.release_method,
        status: row.status,
        createdAt: row.created_at,
        resident: {
            name: resident.name,
            email: resident.email,
            address: resident.address,
            contact: resident.contact
        }
    };

}


async function buildRequests(rows) {

    if (rows.length === 0) {

        return [];

    }

    let ids = rows.map(function(row) {

        return row.resident_id;

    });

    let accounts = await dbCall("GET", "accounts", "?select=*&id=in.(" + ids.join(",") + ")");

    return rows.map(function(row) {

        let owner = accounts.find(function(account) {

            return account.id === row.resident_id;

        }) || {};

        return makeRequest(row, owner);

    });

}


async function getUser(req) {

    let token = text(req.headers.authorization).replace("Bearer ", "");

    let id = readToken(token);

    if (!id) {

        return null;

    }

    let rows = await dbCall("GET", "accounts", "?select=*&" + eq("id", id));

    return rows[0] || null;

}


async function register(body, res) {

    let name = text(body.name);
    let email = cleanEmail(body.email);
    let password = text(body.password);
    let address = text(body.address);
    let contact = text(body.contact);

    if (!name || !email || !password || !address || !contact) {

        return send(res, 400, { message: "Please fill in every field." });

    }

    let existing = await dbCall("GET", "accounts", "?select=id&" + eq("email", email));

    if (existing.length > 0) {

        return send(res, 409, { message: "That email is already registered." });

    }

    await dbCall("POST", "accounts", "", {
        role: "resident",
        name: name,
        email: email,
        password_hash: await bcrypt.hash(password, 10),
        address: address,
        contact: contact
    });

    send(res, 201, { message: "Account created" });

}


// portal = the sign-in page that was used. The role must match it, so staff
// cannot sign in as residents and residents cannot sign in as staff.
async function login(body, res) {

    let rows = await dbCall("GET", "accounts", "?select=*&" + eq("email", cleanEmail(body.email)));

    let account = rows[0];

    let passwordIsRight = account &&
        account.role === body.portal &&
        await bcrypt.compare(text(body.password), account.password_hash);

    if (!passwordIsRight) {

        return send(res, 401, { message: "Wrong email or password." });

    }

    send(res, 200, { token: makeToken(account.id), user: makeUser(account) });

}


// There is no email service, so the reset code is printed in the server log
// (on Render: your service > Logs).
async function forgotPassword(body, res) {

    let email = cleanEmail(body.email);

    let rows = await dbCall("GET", "accounts", "?select=*&" + eq("email", email));

    let account = rows[0];

    if (account && account.role === body.portal) {

        let code = String(Math.floor(100000 + Math.random() * 900000));

        await dbCall("PATCH", "accounts", "?" + eq("id", account.id), {
            reset_code_hash: await bcrypt.hash(code, 10),
            reset_expires_at: new Date(Date.now() + 15 * 60 * 1000).toISOString()
        });

        console.log("Reset code for " + email + ": " + code);

    }

    // The same answer whether the email exists or not
    send(res, 200, { message: "If that email is registered, a reset code was sent." });

}


async function resetPassword(body, res) {

    let newPassword = text(body.newPassword);

    if (!newPassword) {

        return send(res, 400, { message: "Please enter a new password." });

    }

    let rows = await dbCall("GET", "accounts", "?select=*&" + eq("email", cleanEmail(body.email)));

    let account = rows[0];

    let codeIsRight = account &&
        account.role === body.portal &&
        account.reset_code_hash &&
        new Date(account.reset_expires_at) > new Date() &&
        await bcrypt.compare(text(body.code), account.reset_code_hash);

    if (!codeIsRight) {

        return send(res, 400, { message: "That code is not valid or has expired." });

    }

    await dbCall("PATCH", "accounts", "?" + eq("id", account.id), {
        password_hash: await bcrypt.hash(newPassword, 10),
        reset_code_hash: null,
        reset_expires_at: null
    });

    send(res, 200, { message: "Password changed" });

}


async function updateProfile(body, user, res) {

    let name = text(body.name);

    if (!name) {

        return send(res, 400, { message: "Please enter your name." });

    }

    let rows = await dbCall("PATCH", "accounts", "?" + eq("id", user.id), {
        name: name,
        address: text(body.address),
        contact: text(body.contact)
    });

    send(res, 200, makeUser(rows[0]));

}


async function listResidents(user, res) {

    if (user.role !== "staff") {

        return send(res, 403, { message: "Staff only." });

    }

    let rows = await dbCall("GET", "accounts", "?select=*&" + eq("role", "resident") + "&order=id.desc");

    send(res, 200, rows.map(makeUser));

}


async function createRequest(body, user, res) {

    let purpose = text(body.purpose);

    if (!body.documentType || !body.releaseMethod || !purpose) {

        return send(res, 400, { message: "Please fill in every field." });

    }

    let rows = await dbCall("POST", "requests", "", {
        resident_id: user.id,
        document_type: body.documentType,
        purpose: purpose,
        release_method: body.releaseMethod,
        status: "Pending"
    });

    let list = await buildRequests(rows);

    send(res, 201, list[0]);

}


// Residents see their own requests. Staff see all of them.
async function listRequests(user, res) {

    let query = "?select=*&order=id.desc";

    if (user.role !== "staff") {

        query += "&" + eq("resident_id", user.id);

    }

    let rows = await dbCall("GET", "requests", query);

    send(res, 200, await buildRequests(rows));

}


async function getRequest(id, user, res) {

    let rows = await dbCall("GET", "requests", "?select=*&" + eq("id", id));

    let row = rows[0];

    // Residents can only open their own requests
    if (!row || (user.role !== "staff" && row.resident_id !== user.id)) {

        return send(res, 404, { message: "Request not found." });

    }

    let list = await buildRequests([row]);

    send(res, 200, list[0]);

}


async function changeStatus(id, body, user, res) {

    if (user.role !== "staff") {

        return send(res, 403, { message: "Staff only." });

    }

    let rows = await dbCall("PATCH", "requests", "?" + eq("id", id), {
        status: body.status,
        updated_at: new Date().toISOString()
    });

    if (rows.length === 0) {

        return send(res, 404, { message: "Request not found." });

    }

    let list = await buildRequests(rows);

    send(res, 200, list[0]);

}


const server = http.createServer(async function(req, res) {

    // Lets the website pages call this server
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS");

    if (req.method === "OPTIONS") {

        res.writeHead(204);

        return res.end();

    }

    try {

        let body = await readBody(req);
        let method = req.method;
        let path = new URL(req.url, "http://localhost").pathname;

        if (method === "POST" && path === "/api/register") {

            return await register(body, res);

        }

        if (method === "POST" && path === "/api/login") {

            return await login(body, res);

        }

        if (method === "POST" && path === "/api/forgot-password") {

            return await forgotPassword(body, res);

        }

        if (method === "POST" && path === "/api/reset-password") {

            return await resetPassword(body, res);

        }


        // Everything below needs a signed-in person
        let user = await getUser(req);

        if (!user) {

            return send(res, 401, { message: "Please sign in again." });

        }

        if (path === "/api/profile" && method === "GET") {

            return send(res, 200, makeUser(user));

        }

        if (path === "/api/profile" && method === "PUT") {

            return await updateProfile(body, user, res);

        }

        if (path === "/api/residents" && method === "GET") {

            return await listResidents(user, res);

        }

        if (path === "/api/requests" && method === "POST") {

            return await createRequest(body, user, res);

        }

        if (path === "/api/requests" && method === "GET") {

            return await listRequests(user, res);

        }


        // "/api/requests/12/status" becomes ["", "api", "requests", "12", "status"]
        let parts = path.split("/");

        if (parts[2] === "requests" && parts[3]) {

            let id = Number(parts[3]) || 0;

            if (method === "GET" && parts.length === 4) {

                return await getRequest(id, user, res);

            }

            if (method === "PUT" && parts[4] === "status") {

                return await changeStatus(id, body, user, res);

            }

        }

        send(res, 404, { message: "Not found." });

    } catch (error) {

        console.log("Error:", error);

        send(res, 500, { message: "Something went wrong. Try again." });

    }

});


server.listen(process.env.PORT || 3000, function() {

    console.log("API is running");

});
